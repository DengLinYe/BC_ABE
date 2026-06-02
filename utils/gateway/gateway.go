package gateway

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"bc_abe/utils/apperr"
	"bc_abe/utils/logger"
	"bc_abe/utils/pathutil"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	instance *Gateway
	once     sync.Once
	log      = logger.New("gateway")
)

// Gateway Fabric Gateway 单例。
type Gateway struct {
	conn     *grpc.ClientConn
	gateway  *client.Gateway
	network  *client.Network
	contract *client.Contract
	mspID    string
	orgName  string
	channel  string
	ccName   string
}

// Options 连接参数。
type Options struct {
	OrgName       string
	MSPID         string
	CertPEM       string
	KeyPEM        string
	TLSCertPath   string
	PeerEndpoint  string
	GatewayPeer   string
	ChannelName   string
	ChaincodeName string
}

// New 创建独立 Gateway 连接（不占用单例）。
func New(opts Options) (*Gateway, error) {
	return connect(opts)
}

// Init 初始化 Gateway 单例。
func Init(opts Options) (*Gateway, error) {
	var initErr error
	once.Do(func() {
		gw, err := connect(opts)
		if err != nil {
			initErr = err
			return
		}
		instance = gw
	})
	return instance, initErr
}

// Get 返回 Gateway 单例。
func Get() *Gateway {
	return instance
}

// Contract 返回链码合约句柄。
func (g *Gateway) Contract() *client.Contract {
	return g.contract
}

// OrgName 返回组织名。
func (g *Gateway) OrgName() string {
	return g.orgName
}

// Close 关闭连接。
func (g *Gateway) Close() {
	if g.gateway != nil {
		g.gateway.Close()
	}
	if g.conn != nil {
		_ = g.conn.Close()
	}
}

func connect(opts Options) (*Gateway, error) {
	cert, err := loadCertificate(opts.CertPEM)
	if err != nil {
		return nil, apperr.Wrap(apperr.ErrGatewayConnect, "load cert", err)
	}
	key, err := identity.PrivateKeyFromPEM([]byte(opts.KeyPEM))
	if err != nil {
		return nil, apperr.Wrap(apperr.ErrGatewayConnect, "load key", err)
	}
	id, err := identity.NewX509Identity(opts.MSPID, cert)
	if err != nil {
		return nil, apperr.Wrap(apperr.ErrGatewayConnect, "new identity", err)
	}
	sign, err := identity.NewPrivateKeySign(key)
	if err != nil {
		return nil, apperr.Wrap(apperr.ErrGatewayConnect, "new signer", err)
	}

	tlsCert, err := os.ReadFile(opts.TLSCertPath)
	if err != nil {
		return nil, apperr.Wrap(apperr.ErrGatewayConnect, "read tls cert", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(tlsCert) {
		return nil, apperr.Wrap(apperr.ErrGatewayConnect, "parse tls cert", fmt.Errorf("invalid pem"))
	}
	transport := credentials.NewClientTLSFromCert(certPool, opts.GatewayPeer)

	conn, err := grpc.NewClient(opts.PeerEndpoint, grpc.WithTransportCredentials(transport))
	if err != nil {
		return nil, apperr.Wrap(apperr.ErrGatewayConnect, "grpc dial", err)
	}

	gw, err := client.Connect(id, client.WithSign(sign), client.WithHash(hash.SHA256),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		_ = conn.Close()
		return nil, apperr.Wrap(apperr.ErrGatewayConnect, "gateway connect", err)
	}

	network := gw.GetNetwork(opts.ChannelName)
	contract := network.GetContract(opts.ChaincodeName)
	log.Info("gateway connected org=%s channel=%s cc=%s", opts.OrgName, opts.ChannelName, opts.ChaincodeName)

	return &Gateway{
		conn: conn, gateway: gw, network: network, contract: contract,
		mspID: opts.MSPID, orgName: opts.OrgName, channel: opts.ChannelName, ccName: opts.ChaincodeName,
	}, nil
}

func loadCertificate(certPEM string) (*x509.Certificate, error) {
	if certPEM == "" {
		return nil, fmt.Errorf("empty cert pem")
	}
	return identity.CertificateFromPEM([]byte(certPEM))
}

// DefaultOrg1Options 生成 org1 默认连接参数。
func DefaultOrg1Options(channel, ccName string) (Options, error) {
	return DefaultOrgOptions("org1", channel, ccName)
}

// DefaultOrgOptions 按组织名生成 Gateway 连接参数。
func DefaultOrgOptions(orgName, channel, ccName string) (Options, error) {
	orgDomain := "org1.example.com"
	mspID := "Org1MSP"
	peerPort := "localhost:7051"
	if orgName == "org2" {
		orgDomain = "org2.example.com"
		mspID = "Org2MSP"
		peerPort = "localhost:19051"
	}
	base := filepath.Join(pathutil.Abs("./pkg/fabric/test-network/organizations/peerOrganizations"), orgDomain)
	cert, key, err := loadAdminFromBase(base, orgDomain)
	if err != nil {
		return Options{}, err
	}
	return Options{
		OrgName:       orgName,
		MSPID:         mspID,
		CertPEM:       cert,
		KeyPEM:        key,
		TLSCertPath:   filepath.Join(base, "peers/peer0."+orgDomain+"/tls/ca.crt"),
		PeerEndpoint:  peerPort,
		GatewayPeer:   "peer0." + orgDomain,
		ChannelName:   channel,
		ChaincodeName: ccName,
	}, nil
}

func loadAdminFromBase(base, orgDomain string) (string, string, error) {
	mspDir := filepath.Join(base, "users/Admin@"+orgDomain+"/msp")
	cert, err := readFirstFile(filepath.Join(mspDir, "signcerts"))
	if err != nil {
		return "", "", err
	}
	key, err := readFirstFile(filepath.Join(mspDir, "keystore"))
	if err != nil {
		return "", "", err
	}
	return cert, key, nil
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
