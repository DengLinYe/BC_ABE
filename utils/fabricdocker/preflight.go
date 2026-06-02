package fabricdocker

import (
	"fmt"
	"strings"

	"bc_abe/utils/apperr"
)

var requiredCAContainers = []string{"ca_org1", "ca_org2", "ca_orderer"}
var requiredCoreContainers = []string{"orderer.example.com", "peer0.org1.example.com", "peer0.org2.example.com"}

// VerifyCAContainersRunning 确认 Fabric CA 容器均已启动（部署证书生成的前置条件）。
func VerifyCAContainersRunning() error {
	var missing []string
	for _, name := range requiredCAContainers {
		status, err := dockerOutput("inspect", "-f", "{{.State.Running}}", name)
		if err != nil || strings.TrimSpace(status) != "true" {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return apperr.Wrap(apperr.ErrFabricNetwork, "fabric CA not running",
		fmt.Errorf("%s (WSL2 常见原因：宿主机端口 9054/9051/9443 无法转发；已映射 19054/19051，请先菜单 4 清理后重试)", strings.Join(missing, ", ")))
}

// VerifyCoreContainersRunning 确认 orderer/peer 容器均已恢复。
func VerifyCoreContainersRunning() error {
	var missing []string
	for _, name := range requiredCoreContainers {
		status, err := dockerOutput("inspect", "-f", "{{.State.Running}}", name)
		if err != nil || strings.TrimSpace(status) != "true" {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return apperr.Wrap(apperr.ErrFabricNetwork, "fabric core containers not running",
		fmt.Errorf("%s (若 Docker Desktop/WSL 被中断，请先尝试恢复；失败再完整清理后部署)", strings.Join(missing, ", ")))
}
