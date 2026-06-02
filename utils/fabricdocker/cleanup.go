package fabricdocker

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"bc_abe/utils/apperr"
	"bc_abe/utils/logger"
)

var log = logger.New("fabricdocker")

// DefaultContainerNames test-network 使用的固定容器名。
var DefaultContainerNames = []string{
	"peer0.org1.example.com",
	"peer0.org2.example.com",
	"orderer.example.com",
	"ca_org1",
	"ca_org2",
	"ca_orderer",
	"couchdb0",
	"couchdb1",
}

var fabricImagePrefixes = []string{
	"hyperledger/fabric-peer",
	"hyperledger/fabric-orderer",
	"hyperledger/fabric-ca",
	"hyperledger/fabric-ccenv",
	"hyperledger/fabric-baseos",
}

// CleanupOptions 容器清理参数。
type CleanupOptions struct {
	ContainerNames []string
}

// Cleanup 停止并删除 Fabric 相关容器（含 network.sh 未覆盖的残留）。
func Cleanup(opts CleanupOptions) error {
	names := opts.ContainerNames
	if len(names) == 0 {
		names = DefaultContainerNames
	}

	removeByNames(names)
	removeByLabel("service=hyperledger-fabric")
	removeByNamePrefix("dev-peer")
	removeByNamePrefix("ccaas")
	removeByNameSuffix("_ccaas")
	removeChaincodeImages()
	removeByFabricImages()
	removeNetwork("fabric_test")

	log.Info("fabric docker cleanup finished")
	return nil
}

func removeByNames(names []string) {
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if err := docker("rm", "-f", name); err != nil {
			log.Debug("remove container %s: %v", name, err)
		} else {
			log.Info("removed container: %s", name)
		}
	}
}

func removeByLabel(label string) {
	ids, err := dockerOutput("ps", "-aq", "--filter", "label="+label)
	if err != nil {
		log.Warn("list containers by label %s: %v", label, err)
		return
	}
	removeIDs(splitLines(ids))
}

func removeByNamePrefix(prefix string) {
	ids, err := dockerOutput("ps", "-aq", "--filter", "name="+prefix)
	if err != nil {
		log.Warn("list containers by name %s: %v", prefix, err)
		return
	}
	removeIDs(splitLines(ids))
}

func removeByNameSuffix(suffix string) {
	lines, err := dockerOutput("ps", "-aq", "--format", "{{.ID}}\t{{.Names}}")
	if err != nil {
		log.Warn("list containers by suffix %s: %v", suffix, err)
		return
	}
	for _, line := range splitLines(lines) {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.HasSuffix(parts[1], suffix) {
			removeIDs([]string{parts[0]})
		}
	}
}

func removeChaincodeImages() {
	ids, err := dockerOutput("images", "-q", "--filter", "reference=*_ccaas_image")
	if err != nil || ids == "" {
		return
	}
	for _, id := range splitLines(ids) {
		if err := docker("rmi", "-f", id); err != nil {
			log.Debug("remove chaincode image %s: %v", id, err)
		}
	}
}

func removeByFabricImages() {
	lines, err := dockerOutput("ps", "-aq", "--format", "{{.ID}}\t{{.Image}}")
	if err != nil {
		log.Warn("list containers for image cleanup: %v", err)
		return
	}
	for _, line := range splitLines(lines) {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		if matchesFabricImage(parts[1]) {
			removeIDs([]string{parts[0]})
		}
	}
}

func matchesFabricImage(image string) bool {
	image = strings.ToLower(image)
	for _, prefix := range fabricImagePrefixes {
		if strings.HasPrefix(image, prefix) {
			return true
		}
	}
	return false
}

func removeIDs(ids []string) {
	if len(ids) == 0 {
		return
	}
	args := append([]string{"rm", "-f"}, ids...)
	if err := docker(args...); err != nil {
		log.Warn("remove containers %v: %v", ids, err)
	} else {
		log.Info("removed containers: %s", strings.Join(ids, ", "))
	}
}

func removeNetwork(name string) {
	if err := docker("network", "rm", name); err != nil {
		log.Debug("remove network %s: %v", name, err)
	} else {
		log.Info("removed network: %s", name)
	}
}

func docker(args ...string) error {
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return apperr.Wrap(apperr.ErrFabricNetwork, "docker "+strings.Join(args, " "), fmt.Errorf("%v: %s", err, bytes.TrimSpace(out)))
	}
	return nil
}

func dockerOutput(args ...string) (string, error) {
	cmd := exec.Command("docker", args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func splitLines(raw string) []string {
	if raw == "" {
		return nil
	}
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
