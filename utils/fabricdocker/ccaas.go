package fabricdocker

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"bc_abe/utils/config"
	"bc_abe/utils/logger"
)

var ccaasLog = logger.New("fabricdocker/ccaas")

const ccaasReadyRetries = 5

// EnsureCCAASContainers 在 peer 已启动时拉起链码 CCAAS 容器（暂停/崩溃后文件列表与链上查询依赖此服务）。
func EnsureCCAASContainers(cfg config.Config) error {
	if strings.EqualFold(cfg.ChaincodeDeploy, "legacy") {
		return nil
	}
	ccName := chaincodeName(cfg)
	image := ccName + "_ccaas_image:latest"
	if err := dockerImageExists(image); err != nil {
		return err
	}
	packageID, err := resolvePackageID(cfg, ccName)
	if err != nil {
		return err
	}
	if err := savePackageID(cfg, packageID); err != nil {
		ccaasLog.Warn("save package id: %v", err)
	}
	names := ccaasContainerNames(ccName)
	var startErr error
	for _, name := range names {
		if running, _ := containerRunning(name); running {
			continue
		}
		if err := startCCAAS(name, image, packageID); err != nil {
			ccaasLog.Warn("start %s: %v", name, err)
			startErr = err
		} else {
			ccaasLog.Info("started %s", name)
		}
	}
	for _, name := range names {
		running, _ := containerRunning(name)
		if !running {
			if startErr == nil {
				startErr = fmt.Errorf("container %s not running", name)
			}
		}
	}
	return startErr
}

// StopCCAASContainers 暂停网络时停止 CCAAS 链码容器。
func StopCCAASContainers(cfg config.Config) {
	ccName := chaincodeName(cfg)
	for _, name := range ccaasContainerNames(ccName) {
		if err := exec.Command("docker", "stop", name).Run(); err == nil {
			ccaasLog.Info("stopped %s", name)
		}
	}
}

func chaincodeName(cfg config.Config) string {
	if cfg.ChaincodeName != "" {
		return cfg.ChaincodeName
	}
	return "abe_cc"
}

func ccaasContainerNames(ccName string) []string {
	return []string{"peer0org1_" + ccName + "_ccaas", "peer0org2_" + ccName + "_ccaas"}
}

func packageIDCachePath(cfg config.Config) string {
	return filepath.Join(cfg.DataDir, "fabric", "ccaas_package_id.txt")
}

func savePackageID(cfg config.Config, id string) error {
	path := packageIDCachePath(cfg)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.TrimSpace(id)+"\n"), 0o644)
}

func loadPackageID(cfg config.Config) string {
	b, err := os.ReadFile(packageIDCachePath(cfg))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func resolvePackageID(cfg config.Config, ccName string) (string, error) {
	var lastErr error
	for i := 0; i < ccaasReadyRetries; i++ {
		if i > 0 {
			time.Sleep(2 * time.Second)
		}
		id, err := queryInstalledPackageID(cfg, ccName)
		if err == nil && id != "" {
			return id, nil
		}
		lastErr = err
	}
	if cached := loadPackageID(cfg); cached != "" {
		ccaasLog.Warn("query installed failed (%v), using cached package id", lastErr)
		return cached, nil
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("no installed package for %s", ccName)
}

func dockerImageExists(image string) error {
	cmd := exec.Command("docker", "image", "inspect", image)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("chaincode image %s not found; deploy chaincode first", image)
	}
	return nil
}

func queryInstalledPackageID(cfg config.Config, ccName string) (string, error) {
	peerBin := filepath.Join(cfg.FabricBinDir, "peer")
	cmd := exec.Command(peerBin, "lifecycle", "chaincode", "queryinstalled", "--output", "json")
	cmd.Dir = cfg.FabricNetworkDir
	cmd.Env = append(os.Environ(), org1AdminPeerEnv(cfg)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("query installed chaincode: %w: %s", err, strings.TrimSpace(string(out)))
	}
	var parsed struct {
		InstalledChaincodes []struct {
			PackageID string `json:"package_id"`
			Label     string `json:"label"`
		} `json:"installed_chaincodes"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return "", err
	}
	prefix := ccName + "_"
	for _, cc := range parsed.InstalledChaincodes {
		if strings.HasPrefix(cc.Label, prefix) || strings.HasPrefix(cc.PackageID, prefix) {
			return cc.PackageID, nil
		}
	}
	return "", fmt.Errorf("no installed package for %s", ccName)
}

func org1AdminPeerEnv(cfg config.Config) []string {
	orgDir := filepath.Join(cfg.FabricNetworkDir, "organizations/peerOrganizations/org1.example.com")
	fabricCfg := filepath.Join(filepath.Dir(cfg.FabricNetworkDir), "config")
	return []string{
		"CORE_PEER_LOCALMSPID=" + cfg.MSPIDOrg1,
		"CORE_PEER_MSPCONFIGPATH=" + filepath.Join(orgDir, "users/Admin@org1.example.com/msp"),
		"CORE_PEER_TLS_ROOTCERT_FILE=" + filepath.Join(orgDir, "tlsca/tlsca.org1.example.com-cert.pem"),
		"CORE_PEER_TLS_ENABLED=true",
		"CORE_PEER_ADDRESS=localhost:7051",
		"FABRIC_CFG_PATH=" + fabricCfg,
	}
}

func containerRunning(name string) (bool, error) {
	cmd := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) == "true", nil
}

func startCCAAS(name, image, packageID string) error {
	_ = exec.Command("docker", "rm", "-f", name).Run()
	cmd := exec.Command("docker", "run", "-d", "--name", name,
		"--network", "fabric_test",
		"-e", "CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999",
		"-e", "CHAINCODE_ID="+packageID,
		"-e", "CORE_CHAINCODE_ID_NAME="+packageID,
		image,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}
