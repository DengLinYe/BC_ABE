package fabricdocker

import (
	"fmt"
	"strings"

	"bc_abe/utils/apperr"
)

var requiredCAContainers = []string{"ca_org1", "ca_org2", "ca_orderer"}

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
		fmt.Errorf("%s (若 ca_org2 失败，常见原因是 WSL2 端口 18054 无法转发；已改为不映射 operations 端口，请先执行菜单 4 清理后重试)", strings.Join(missing, ", ")))
}
