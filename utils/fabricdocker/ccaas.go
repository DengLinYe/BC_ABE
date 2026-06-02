package fabricdocker

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"bc_abe/utils/config"
	"bc_abe/utils/logger"
)

var ccaasLog = logger.New("fabricdocker/ccaas")

// EnsureCCAASContainers 在 peer 已启动时拉起链码 CCAAS 容器（暂停/崩溃后文件列表与链上查询依赖此服务）。
func EnsureCCAASContainers(cfg config.Config) error {
	ccName := cfg.ChaincodeName
	if ccName == "" {
		ccName = "abe_cc"
	}
	image := ccName + "_ccaas_image:latest"
	if err := dockerImageExists(image); err != nil {
		return err
	}
	packageID, err := queryInstalledPackageID(ccName)
	if err != nil {
		return err
	}
	for _, name := range []string{"peer0org1_" + ccName + "_ccaas", "peer0org2_" + ccName + "_ccaas"} {
		if running, _ := containerRunning(name); running {
			continue
		}
		if err := startCCAAS(name, image, packageID); err != nil {
			ccaasLog.Warn("start %s: %v", name, err)
		} else {
			ccaasLog.Info("started %s", name)
		}
	}
	return nil
}

func dockerImageExists(image string) error {
	cmd := exec.Command("docker", "image", "inspect", image)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("chaincode image %s not found; run menu 5 (deploy chaincode) first", image)
	}
	return nil
}

func queryInstalledPackageID(ccName string) (string, error) {
	cmd := exec.Command("docker", "exec", "peer0.org1.example.com",
		"peer", "lifecycle", "chaincode", "queryinstalled", "--output", "json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("query installed chaincode: %w: %s", err, string(out))
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
