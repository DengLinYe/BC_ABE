package config

import (
	"os"
	"strconv"
	"strings"
	"sync"

	"bc_abe/utils/pathutil"

	"github.com/joho/godotenv"
)

// Config 系统环境配置。
type Config struct {
	ProjectRoot       string
	AppEnv            string
	LogLevel          string
	LogDir            string
	DataDir           string
	MySQLDSN          string
	FabricNetworkDir  string
	FabricBinDir      string
	ChaincodeName     string
	ChaincodeDeploy   string // ccaas | legacy
	ChannelName       string
	UserClientPort    int
	AuthAdminOrg1Port int
	AuthAdminOrg2Port int
	FabricCAOrg1URL   string
	FabricCAOrg2URL   string
	FabricCAAdminUser string
	FabricCAAdminPass string
	ABESeed           string
	MSPIDOrg1         string
	MSPIDOrg2         string
	AuthNameOrg1      string
	AuthNameOrg2      string
	FabricContainers  []string
}

var (
	cfg  Config
	once sync.Once
)

// Load 从 .env 加载配置，路径均相对项目根目录解析。
func Load() Config {
	once.Do(func() {
		root := pathutil.Root()
		_ = godotenv.Load(pathutil.Abs(".env"))
		cfg = Config{
			ProjectRoot:       root,
			AppEnv:            getEnv("APP_ENV", "development"),
			LogLevel:          getEnv("LOG_LEVEL", "info"),
			LogDir:            pathutil.Abs(getEnv("LOG_DIR", "./data/logs")),
			DataDir:           pathutil.Abs(getEnv("DATA_DIR", "./data")),
			MySQLDSN:          getEnv("MYSQL_DSN", "root:123456@tcp(127.0.0.1:3306)/bc_abe?charset=utf8mb4&parseTime=True&loc=Local"),
			FabricNetworkDir:  pathutil.Abs(getEnv("FABRIC_NETWORK_DIR", "./pkg/fabric/test-network")),
			FabricBinDir:      pathutil.Abs(getEnv("FABRIC_BIN_DIR", "./pkg/fabric/bin")),
			ChaincodeName:     getEnv("CHAINCODE_NAME", "abe_cc"),
			ChaincodeDeploy:   getEnv("CHAINCODE_DEPLOY", "ccaas"),
			ChannelName:       getEnv("CHANNEL_NAME", "mychannel"),
			UserClientPort:    getEnvInt("USER_CLIENT_PORT", 8080),
			AuthAdminOrg1Port: getEnvInt("AUTH_ADMIN_ORG1_PORT", 8091),
			AuthAdminOrg2Port: getEnvInt("AUTH_ADMIN_ORG2_PORT", 8092),
			FabricCAOrg1URL:   getEnv("FABRIC_CA_ORG1_URL", "https://localhost:7054"),
			FabricCAOrg2URL:   getEnv("FABRIC_CA_ORG2_URL", "https://localhost:8054"),
			FabricCAAdminUser: getEnv("FABRIC_CA_ADMIN_USER", "admin"),
			FabricCAAdminPass: getEnv("FABRIC_CA_ADMIN_PASS", "adminpw"),
			ABESeed:           getEnv("ABE_SEED", "bc-abe-demo-seed"),
			MSPIDOrg1:         getEnv("MSP_ID_ORG1", "Org1MSP"),
			MSPIDOrg2:         getEnv("MSP_ID_ORG2", "Org2MSP"),
			AuthNameOrg1:      getEnv("AUTH_NAME_ORG1", "auth0"),
			AuthNameOrg2:      getEnv("AUTH_NAME_ORG2", "auth1"),
			FabricContainers:  splitContainers(getEnv("FABRIC_CONTAINERS", "peer0.org1.example.com,peer0.org2.example.com,orderer.example.com,ca_org1,ca_org2,ca_orderer")),
		}
	})
	return cfg
}

func splitContainers(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func AuthNameForOrg(orgName string) string {
	cfg := Load()
	if strings.EqualFold(orgName, "org2") {
		return cfg.AuthNameOrg2
	}
	return cfg.AuthNameOrg1
}

func MSPIDForOrg(orgName string) string {
	cfg := Load()
	if strings.EqualFold(orgName, "org2") {
		return cfg.MSPIDOrg2
	}
	return cfg.MSPIDOrg1
}

func CAURLForOrg(orgName string) string {
	cfg := Load()
	if strings.EqualFold(orgName, "org2") {
		return cfg.FabricCAOrg2URL
	}
	return cfg.FabricCAOrg1URL
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
