package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"bc_abe/utils/apperr"
	"bc_abe/utils/config"
	"bc_abe/utils/db"
	"bc_abe/utils/fabricdocker"
	"bc_abe/utils/logger"
	"bc_abe/utils/pathutil"
)

var log = logger.New("main")

// Orchestrator 总端编排器。
type Orchestrator struct {
	cfg config.Config
	wg  sync.WaitGroup
	mu  sync.Mutex
}

func main() {
	cfg := config.Load()
	logger.Init(cfg.LogDir, cfg.LogLevel)

	orch := &Orchestrator{cfg: cfg}
	log.Info("project root: %s", cfg.ProjectRoot)
	log.Info("chaincode deploy mode: %s (use CHAINCODE_DEPLOY=legacy for deployCC)", cfg.ChaincodeDeploy)
	go handleSignals(orch)
	runMenu(orch)
}

func handleSignals(orch *Orchestrator) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	orch.Shutdown()
	os.Exit(0)
}

func runMenu(orch *Orchestrator) {
	reader := bufio.NewReader(os.Stdin)
	for {
		printMenu()
		fmt.Print("请选择: ")
		line, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(line)
		switch choice {
		case "1":
			if err := orch.FullClean(); err != nil {
				log.Error("清理失败: %v", err)
			}
		case "2":
			if err := orch.DeployNetwork(true); err != nil {
				log.Error("部署网络失败: %v", err)
			}
		case "3":
			if err := orch.PauseNetwork(); err != nil {
				log.Error("暂停失败: %v", err)
			}
		case "4":
			if err := orch.ResumeNetwork(); err != nil {
				log.Error("恢复失败: %v", err)
			}
		case "5":
			if err := orch.DeployChaincode(); err != nil {
				log.Error("部署链码失败: %v", err)
			}
		case "0", "q", "Q":
			orch.Shutdown()
			return
		default:
			fmt.Println("无效选项")
		}
	}
}

func printMenu() {
	fmt.Println("\n========== BC ABE 区块链控制台 ==========")
	fmt.Println(" 1) 清理区块链与衍生数据 (完整回到 0 状态)")
	fmt.Println(" 2) 部署区块链 (network.sh up + 链码)")
	fmt.Println(" 3) 暂停区块链 (保留账本/证书/数据库)")
	fmt.Println(" 4) 恢复区块链 (从暂停状态 docker start)")
	fmt.Println(" 5) 部署链码 (CCAAS，推荐 WSL2)")
	fmt.Println(" 0) 退出")
	fmt.Println("===================================")
}

func (o *Orchestrator) StartContainers() error {
	for _, name := range o.cfg.FabricContainers {
		if err := o.docker("start", name); err != nil {
			log.Warn("start %s: %v", name, err)
		} else {
			log.Info("container started: %s", name)
		}
	}
	return nil
}

// PauseNetwork 停止 Fabric 容器但保留证书、账本卷、数据库和本地文件。
func (o *Orchestrator) PauseNetwork() error {
	log.Info("pausing fabric containers (persistent data kept)")
	fabricdocker.StopCCAASContainers(o.cfg)
	return o.StopContainers()
}

// ResumeNetwork 从暂停状态恢复 Fabric 容器，并确保 CCAAS 链码可用。
func (o *Orchestrator) ResumeNetwork() error {
	log.Info("resuming fabric containers from paused state")
	if err := o.StartContainers(); err != nil {
		return err
	}
	if err := fabricdocker.VerifyCoreContainersRunning(); err != nil {
		return err
	}
	return o.ensureChaincodeReady()
}

// ensureChaincodeReady 恢复或部署链码，保证 user_client 链上接口可用。
func (o *Orchestrator) ensureChaincodeReady() error {
	if strings.EqualFold(o.cfg.ChaincodeDeploy, "legacy") {
		return nil
	}
	if err := fabricdocker.EnsureCCAASContainers(o.cfg); err == nil {
		log.Info("ccaas chaincode containers ready")
		return nil
	} else {
		log.Warn("ccaas ensure failed: %v; redeploying chaincode", err)
	}
	return o.DeployChaincode()
}

func (o *Orchestrator) StopContainers() error {
	for _, name := range o.cfg.FabricContainers {
		if err := o.docker("stop", name); err != nil {
			log.Warn("stop %s: %v", name, err)
		} else {
			log.Info("container stopped: %s", name)
		}
	}
	return nil
}

// FullClean 清理 Fabric 容器、网络产物、账本卷以及本系统衍生数据，回到 0 状态。
func (o *Orchestrator) FullClean() error {
	log.Info("full cleanup: fabric containers, artifacts, ledger volumes, local data")
	if err := o.StopNetwork(); err != nil {
		return err
	}
	if err := fabricdocker.CleanupVolumes(); err != nil {
		log.Warn("cleanup docker volumes: %v", err)
	}
	for _, rel := range []string{
		"files",
		"db",
		"fabric-ca-registrar",
	} {
		p := filepath.Join(o.cfg.DataDir, rel)
		if err := os.RemoveAll(p); err != nil {
			return apperr.Wrap(apperr.ErrFabricNetwork, "remove data/"+rel, err)
		}
		log.Info("removed data path: %s", p)
	}
	for _, rel := range []string{"auth_admin/data", "user_client/data"} {
		p := pathutil.Abs(rel)
		if err := os.RemoveAll(p); err != nil {
			return apperr.Wrap(apperr.ErrFabricNetwork, "remove "+rel, err)
		}
	}
	return nil
}

func (o *Orchestrator) docker(args ...string) error {
	cmd := exec.Command("docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (o *Orchestrator) networkScript(args ...string) error {
	script := filepath.Join(o.cfg.FabricNetworkDir, "network.sh")
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Dir = o.cfg.FabricNetworkDir
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PATH=%s:%s", filepath.Join(pathutil.Abs("./pkg/fabric/bin")), os.Getenv("PATH")),
		fmt.Sprintf("FABRIC_CFG_PATH=%s", filepath.Join(o.cfg.FabricNetworkDir, "..", "config")),
	)
	// cmd.Env = append(os.Environ(), "GOWORK=off")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Info("exec: bash %s %v (cwd=%s)", script, args, cmd.Dir)
	return cmd.Run()
}

func (o *Orchestrator) DeployNetwork(withCC bool) error {
	log.Info("cleaning stale fabric containers before deploy")
	_ = fabricdocker.Cleanup(fabricdocker.CleanupOptions{ContainerNames: o.cfg.FabricContainers})
	if err := fabricdocker.EnsureCryptoMaterial(o.cfg.FabricNetworkDir); err != nil {
		return err
	}
	if err := o.networkScript("up", "createChannel", "-ca"); err != nil {
		return err
	}
	if err := fabricdocker.VerifyCAContainersRunning(); err != nil {
		log.Warn("post-deploy CA check: %v", err)
	}
	_ = os.MkdirAll(filepath.Dir(o.cfg.DBPath), 0o755)
	if _, initErr := db.Init(o.cfg.DBPath); initErr == nil {
		if seedErr := db.SeedFabricUsers(o.cfg); seedErr != nil {
			log.Warn("fabric user seed after deploy: %v", seedErr)
		}
	} else {
		log.Warn("db init for seed: %v", initErr)
	}
	if withCC {
		return o.DeployChaincode()
	}
	return nil
}

func (o *Orchestrator) StopNetwork() error {
	log.Info("stopping fabric containers before network down")
	if err := fabricdocker.Cleanup(fabricdocker.CleanupOptions{ContainerNames: o.cfg.FabricContainers}); err != nil {
		log.Warn("pre-cleanup: %v", err)
	}
	if err := o.networkScript("down"); err != nil {
		log.Warn("network.sh down: %v", err)
	}
	if err := fabricdocker.Cleanup(fabricdocker.CleanupOptions{ContainerNames: o.cfg.FabricContainers}); err != nil {
		log.Warn("post-cleanup containers: %v", err)
	}
	if err := fabricdocker.WipeNetworkArtifacts(o.cfg.FabricNetworkDir); err != nil {
		return err
	}
	return nil
}

func (o *Orchestrator) DeployChaincode() error {
	ccPath := pathutil.Abs("./chaincode")
	if _, err := os.Stat(filepath.Join(ccPath, "Dockerfile")); err != nil {
		return apperr.Wrap(apperr.ErrFabricNetwork, "chaincode Dockerfile missing", err)
	}
	if strings.EqualFold(o.cfg.ChaincodeDeploy, "legacy") {
		log.Warn("CHAINCODE_DEPLOY=legacy: peer 内 docker build，WSL2 易失败")
		return o.networkScript("deployCC", "-ccn", o.cfg.ChaincodeName, "-ccp", ccPath, "-ccl", "go")
	}
	log.Info("deploying chaincode via deployCCAAS (host docker build)")
	if err := o.networkScript("deployCCAAS", "-ccn", o.cfg.ChaincodeName, "-ccp", ccPath); err != nil {
		return err
	}
	if err := fabricdocker.EnsureCCAASContainers(o.cfg); err != nil {
		return err
	}
	return nil
}

func (o *Orchestrator) Shutdown() {
	o.wg.Wait()
	time.Sleep(500 * time.Millisecond)
}
