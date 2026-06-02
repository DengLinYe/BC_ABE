package fabricca

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"bc_abe/utils/apperr"
	"bc_abe/utils/config"
)

// EnrollResult Fabric CA 注册并签发的证书与私钥。
type EnrollResult struct {
	CertPEM string
	KeyPEM  string
}

// Client Fabric CA 客户端。
type Client struct {
	cfg     config.Config
	caURL   string
	orgName string
}

// NewClient 创建 Fabric CA 客户端。
func NewClient(orgName string) *Client {
	cfg := config.Load()
	return &Client{cfg: cfg, caURL: config.CAURLForOrg(orgName), orgName: orgName}
}

// RegisterAndEnroll 向 fabric-ca-server 注册用户并签发证书。
func (c *Client) RegisterAndEnroll(username, password string) (*EnrollResult, error) {
	if err := c.register(username, password); err != nil {
		return nil, err
	}
	return c.enroll(username, password)
}

func (c *Client) register(username, password string) error {
	bin := filepath.Join(c.cfg.FabricBinDir, "fabric-ca-client")
	if _, err := os.Stat(bin); err == nil {
		registrarHome, err := c.ensureRegistrarHome()
		if err != nil {
			return err
		}
		cmd := exec.Command(bin, "register",
			"--caname", c.caName(),
			"-u", c.urlWithCredentials(c.cfg.FabricCAAdminUser, c.cfg.FabricCAAdminPass),
			"--tls.certfiles", c.caCertPath(),
			"--home", registrarHome,
			"--id.name", username,
			"--id.secret", password,
			"--id.type", "client",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return apperr.Wrap(apperr.ErrFabricNetwork, "fabric-ca register", fmt.Errorf("%v: %s", err, out))
		}
		return nil
	}
	return c.registerHTTP(username, password)
}

func (c *Client) enroll(username, password string) (*EnrollResult, error) {
	bin := filepath.Join(c.cfg.FabricBinDir, "fabric-ca-client")
	if _, err := os.Stat(bin); err == nil {
		home, err := os.MkdirTemp("", "fca-enroll-*")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(home)
		cmd := exec.Command(bin, "enroll",
			"-u", c.urlWithCredentials(username, password),
			"--caname", c.caName(),
			"--tls.certfiles", c.caCertPath(),
			"--home", home,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, apperr.Wrap(apperr.ErrFabricNetwork, "fabric-ca enroll", fmt.Errorf("%v: %s", err, out))
		}
		cert, err := readFirstFile(filepath.Join(home, "msp/signcerts"))
		if err != nil {
			return nil, err
		}
		key, err := readFirstFile(filepath.Join(home, "msp/keystore"))
		if err != nil {
			return nil, err
		}
		return &EnrollResult{CertPEM: cert, KeyPEM: key}, nil
	}
	return c.enrollHTTP(username, password)
}

func (c *Client) registerHTTP(username, password string) error {
	body := map[string]any{
		"id":              username,
		"type":            "client",
		"secret":          password,
		"max_enrollments": -1,
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(c.caURL, "/")+"/register", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.cfg.FabricCAAdminUser, c.cfg.FabricCAAdminPass)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return apperr.Wrap(apperr.ErrFabricNetwork, "ca register http", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ca register failed: %s", string(b))
	}
	return nil
}

func (c *Client) enrollHTTP(username, password string) (*EnrollResult, error) {
	return nil, apperr.Wrap(apperr.ErrFabricNetwork, "enroll", fmt.Errorf("fabric-ca-client binary required"))
}

func (c *Client) caName() string {
	return "ca-" + c.orgName
}

func (c *Client) caCertPath() string {
	return filepath.Join(c.cfg.FabricNetworkDir, "organizations/fabric-ca", c.orgName, "ca-cert.pem")
}

func (c *Client) ensureRegistrarHome() (string, error) {
	home := filepath.Join(c.cfg.DataDir, "fabric-ca-registrar", c.orgName)
	if _, err := os.Stat(filepath.Join(home, "msp/signcerts")); err == nil {
		return home, nil
	}
	if err := os.MkdirAll(home, 0o755); err != nil {
		return "", err
	}
	bin := filepath.Join(c.cfg.FabricBinDir, "fabric-ca-client")
	cmd := exec.Command(bin, "enroll",
		"-u", c.urlWithCredentials(c.cfg.FabricCAAdminUser, c.cfg.FabricCAAdminPass),
		"--caname", c.caName(),
		"--tls.certfiles", c.caCertPath(),
		"--home", home,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", apperr.Wrap(apperr.ErrFabricNetwork, "fabric-ca registrar enroll", fmt.Errorf("%v: %s", err, out))
	}
	return home, nil
}

func (c *Client) urlWithCredentials(username, password string) string {
	scheme := "https://"
	host := c.caURL
	if strings.HasPrefix(host, "http://") {
		scheme = "http://"
		host = strings.TrimPrefix(host, "http://")
	} else {
		host = strings.TrimPrefix(host, "https://")
	}
	return fmt.Sprintf("%s%s:%s@%s", scheme, username, password, host)
}

func readFirstFile(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return "", fmt.Errorf("no file in %s", dir)
}
