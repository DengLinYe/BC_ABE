package main

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
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
	"bc_abe/utils/gateway"
	"bc_abe/utils/logger"
	"bc_abe/utils/pathutil"
)

var log = logger.New("main")

// Orchestrator 总端编排器。
type Orchestrator struct {
	cfg    config.Config
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
}

func main() {
	cfg := config.Load()
	logger.Init(cfg.LogDir, cfg.LogLevel)
	_ = os.MkdirAll(filepath.Dir(cfg.DBPath), 0o755)
	if _, err := db.Init(cfg.DBPath); err != nil {
		apperr.ExitOn(log, err)
	}
	if err := db.SeedFabricUsers(cfg); err != nil {
		log.Warn("fabric user seed skipped: %v", err)
	}

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
			if err := orch.StartContainers(); err != nil {
				log.Error("启动容器失败: %v", err)
			}
		case "2":
			if err := orch.StopContainers(); err != nil {
				log.Error("停止容器失败: %v", err)
			}
		case "3":
			if err := orch.DeployNetwork(true); err != nil {
				log.Error("部署网络失败: %v", err)
			}
		case "4":
			if err := orch.StopNetwork(); err != nil {
				log.Error("清理网络失败: %v", err)
			}
		case "5":
			if err := orch.DeployChaincode(); err != nil {
				log.Error("部署链码失败: %v", err)
			}
		case "6":
			if err := orch.RunAll(); err != nil {
				log.Error("运行服务失败: %v", err)
			}
		case "7":
			if err := orch.InitializeOrganizations(); err != nil {
				log.Error("初始化组织失败: %v", err)
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
	fmt.Println("\n========== BC ABE 总控台 ==========")
	fmt.Println(" 1) 启动区块链容器 (docker start)")
	fmt.Println(" 2) 停止区块链容器 (docker stop)")
	fmt.Println(" 3) 部署区块链 (network.sh up + 链码)")
	fmt.Println(" 4) 清理区块链 (down + 容器清理 + 证书目录 wipe)")
	fmt.Println(" 5) 部署链码 (CCAAS，推荐 WSL2)")
	fmt.Println(" 6) 启动组织管理端 + 用户客户端")
	fmt.Println(" 7) 初始化组织 ABE 参数并同步上链")
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
	if err := db.SeedFabricUsers(o.cfg); err != nil {
		log.Warn("fabric user seed after deploy: %v", err)
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
	return o.networkScript("deployCCAAS", "-ccn", o.cfg.ChaincodeName, "-ccp", ccPath)
}

func (o *Orchestrator) RunAll() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cancel != nil {
		log.Warn("services already running")
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	o.cancel = cancel

	admins := []struct {
		org  string
		port int
	}{
		{"org1", o.cfg.AuthAdminOrg1Port},
		{"org2", o.cfg.AuthAdminOrg2Port},
	}
	for _, admin := range admins {
		o.wg.Add(1)
		go func(org string, port int) {
			defer o.wg.Done()
			adminLog := logger.New("auth_admin/" + org)
			adminLog.Info("starting on :%d", port)
			cmd := exec.Command("go", "run", ".")
			cmd.Dir = pathutil.Abs("./auth_admin")
			cmd.Env = append(os.Environ(),
				fmt.Sprintf("ORG_NAME=%s", org),
				fmt.Sprintf("BC_ABE_ROOT=%s", o.cfg.ProjectRoot),
			)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				adminLog.Error("start failed: %v", err)
				return
			}
			<-ctx.Done()
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
		}(admin.org, admin.port)
	}

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		log.Info("starting user client on :%d", o.cfg.UserClientPort)
		cmd := exec.Command("go", "run", ".")
		cmd.Dir = pathutil.Abs("./user_client")
		cmd.Env = append(os.Environ(), fmt.Sprintf("BC_ABE_ROOT=%s", o.cfg.ProjectRoot))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			log.Error("user client start failed: %v", err)
			return
		}
		<-ctx.Done()
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
	}()

	opts, err := gateway.DefaultOrg1Options(o.cfg.ChannelName, o.cfg.ChaincodeName)
	if err == nil {
		if _, err := gateway.Init(opts); err != nil {
			log.Warn("gateway init failed: %v", err)
		}
	}

	log.Info("services started")
	return nil
}

func (o *Orchestrator) InitializeOrganizations() error {
	targets := []struct {
		org  string
		port int
	}{
		{"org1", o.cfg.AuthAdminOrg1Port},
		{"org2", o.cfg.AuthAdminOrg2Port},
	}
	client := &http.Client{Timeout: 30 * time.Second}
	for _, t := range targets {
		url := fmt.Sprintf("http://127.0.0.1:%d/api/v1/org/init", t.port)
		resp, err := client.Post(url, "application/json", nil)
		if err != nil {
			return fmt.Errorf("init %s: %w", t.org, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("init %s: http %d", t.org, resp.StatusCode)
		}
		log.Info("organization initialized: %s", t.org)
	}
	return nil
}

func (o *Orchestrator) Shutdown() {
	o.mu.Lock()
	if o.cancel != nil {
		o.cancel()
		o.cancel = nil
	}
	o.mu.Unlock()
	o.wg.Wait()
	time.Sleep(500 * time.Millisecond)
}
