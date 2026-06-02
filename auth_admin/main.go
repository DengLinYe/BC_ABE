package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	abeengine "bc_abe/abe"
	"bc_abe/utils/apperr"
	"bc_abe/utils/config"
	"bc_abe/utils/db"
	"bc_abe/utils/gateway"
	"bc_abe/utils/logger"
	"bc_abe/utils/msp"
)

var log = logger.New("auth_admin")

// Server 组织管理端。
type Server struct {
	orgName  string
	port     int
	engine   *abeengine.Engine
	cfg      config.Config
	caCert   string
	authName string
}

func main() {
	orgName, err := requiredEnv("ORG_NAME")
	if err != nil {
		apperr.ExitOn(log, err)
	}
	cfg := config.Load()
	port := cfg.AuthAdminOrg1Port
	if orgName == "org2" {
		port = cfg.AuthAdminOrg2Port
	}

	logger.Init(cfg.LogDir, cfg.LogLevel)
	if _, err := db.Init(cfg.DBPath); err != nil {
		apperr.ExitOn(log, err)
	}

	s := newServer(orgName, port, cfg)
	if err := s.bootstrapOrg(); err != nil {
		log.Warn("bootstrap org skipped: %v", err)
	}

	addr := fmt.Sprintf(":%d", port)
	log.Info("auth admin for %s listening on %s", orgName, addr)
	if err := http.ListenAndServe(addr, s.handler()); err != nil {
		apperr.ExitOn(log, apperr.Wrap(apperr.ErrInvalidInput, "http server", err))
	}
}

func newServer(orgName string, port int, cfg config.Config) *Server {
	s := &Server{
		orgName:  orgName,
		port:     port,
		engine:   abeengine.NewEngine(cfg.ABESeed),
		cfg:      cfg,
		authName: config.AuthNameForOrg(orgName),
	}
	s.caCert = s.loadCACert()
	return s
}

func (s *Server) loadAdminIdentity() (certPEM, keyPEM string) {
	mspDir := filepath.Join(s.cfg.FabricNetworkDir, "organizations/peerOrganizations", s.orgDomain(), "users/Admin@"+s.orgDomain()+"/msp")
	cert, key, err := msp.LoadIdentityFromMSP(mspDir)
	if err != nil {
		log.Warn("load admin identity failed: %v", err)
		return "", ""
	}
	return cert, key
}

func (s *Server) loadCACert() string {
	orgDomain := s.orgDomain()
	cacertsDir := filepath.Join(s.cfg.FabricNetworkDir, "organizations/peerOrganizations", orgDomain, "users/Admin@"+orgDomain+"/msp/cacerts")
	cert, err := msp.LoadCACertFromMSP(cacertsDir)
	if err != nil {
		log.Warn("load ca cert failed: %v", err)
		return ""
	}
	return cert
}

func (s *Server) orgDomain() string {
	if s.orgName == "org2" {
		return "org2.example.com"
	}
	return "org1.example.com"
}

func requiredEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", apperr.Wrap(apperr.ErrConfig, key+" is required", nil)
	}
	return v, nil
}

func (s *Server) bootstrapOrg() error {
	var org db.Organization
	if err := db.Get().Where("name = ?", s.orgName).First(&org).Error; err != nil {
		return err
	}
	s.authName = org.AuthName
	return s.engine.LoadOrgFromJSON(org.OrgJSON)
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/v1/org/init", s.handleInitOrg)
	mux.HandleFunc("/api/v1/key/issue", s.handleIssueKey)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "org": s.orgName, "authName": s.authName})
}

type initOrgResp struct {
	OrgName     string `json:"orgName"`
	AuthName    string `json:"authName"`
	OrgJSON     string `json:"orgJson"`
	AuthPubJSON string `json:"authPubJson"`
	CurveJSON   string `json:"curveJson"`
}

func (s *Server) handleInitOrg(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.authName = config.AuthNameForOrg(s.orgName)

	var existing db.Organization
	if err := db.Get().Where("name = ?", s.orgName).First(&existing).Error; err == nil &&
		existing.OrgJSON != "" && existing.AuthPubJSON != "" && existing.AuthPrvJSON != "" {
		existing.AuthName = s.authName
		existing.MSPID = config.MSPIDForOrg(s.orgName)
		existing.AdminCertPEM, existing.AdminKeyPEM = s.loadAdminIdentity()
		existing.CACertPEM = s.caCert
		if err := db.Get().Save(&existing).Error; err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.engine.LoadOrgFromJSON(existing.OrgJSON)
		_ = s.engine.LoadAuthFromJSON(existing.AuthPubJSON, existing.AuthPrvJSON)
		s.syncGlobalParamsToChain(existing)
		writeJSON(w, http.StatusOK, initOrgResp{
			OrgName:     s.orgName,
			AuthName:    existing.AuthName,
			OrgJSON:     existing.OrgJSON,
			AuthPubJSON: existing.AuthPubJSON,
			CurveJSON:   existing.CurveJSON,
		})
		return
	}

	if err := s.engine.InitOrg(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.engine.InitAuthority(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	adminCert, adminKey := s.loadAdminIdentity()
	record := db.Organization{
		Name:         s.orgName,
		MSPID:        config.MSPIDForOrg(s.orgName),
		AuthName:     s.authName,
		OrgJSON:      s.engine.OrgJSON(),
		AuthPubJSON:  s.engine.AuthPubJSON(),
		AuthPrvJSON:  s.engine.AuthPrvJSON(),
		CurveJSON:    s.engine.CurveJSON(),
		AdminCertPEM: adminCert,
		AdminKeyPEM:  adminKey,
		CACertPEM:    s.caCert,
	}
	db.Get().Where("name = ?", s.orgName).Assign(record).FirstOrCreate(&record)
	s.syncGlobalParamsToChain(record)

	writeJSON(w, http.StatusOK, initOrgResp{
		OrgName: s.orgName, AuthName: s.authName, OrgJSON: record.OrgJSON,
		AuthPubJSON: record.AuthPubJSON, CurveJSON: record.CurveJSON,
	})
}

func (s *Server) syncGlobalParamsToChain(org db.Organization) {
	opts, err := gateway.DefaultOrgOptions(s.orgName, s.cfg.ChannelName, s.cfg.ChaincodeName)
	if err != nil {
		log.Warn("gateway options failed: %v", err)
		return
	}
	gw, err := gateway.New(opts)
	if err != nil {
		log.Warn("gateway unavailable, skip chain sync: %v", err)
		return
	}
	defer gw.Close()
	pubKeys := map[string]string{}
	raw, err := gw.Contract().EvaluateTransaction("GetGlobalParams")
	if err == nil {
		var existing struct {
			OrgPubKeys map[string]string `json:"orgPubKeys"`
		}
		if err := json.Unmarshal(raw, &existing); err == nil && existing.OrgPubKeys != nil {
			pubKeys = existing.OrgPubKeys
		}
	}
	pubKeys[s.authName] = org.AuthPubJSON
	params := map[string]any{
		"id": "GLOBAL_PARAMS", "curve": org.CurveJSON,
		"orgPubKeys": pubKeys,
		"updatedAt":  time.Now().Format(time.RFC3339),
	}
	payload, _ := json.Marshal(params)
	if _, err := gw.Contract().SubmitTransaction("PutGlobalParams", string(payload)); err != nil {
		log.Warn("sync global params failed: %v", err)
	}
}

type issueKeyReq struct {
	User      string `json:"user"`
	Attribute string `json:"attribute"`
	CertPEM   string `json:"certPem"`
	Signature string `json:"signature"`
	BodyHash  string `json:"bodyHash"`
}

func (s *Server) handleIssueKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req issueKeyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.User == "" || req.Attribute == "" || req.CertPEM == "" || req.Signature == "" {
		writeErr(w, http.StatusBadRequest, "missing fields")
		return
	}
	if err := s.verifyUser(req); err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}

	var org db.Organization
	if err := db.Get().Where("name = ?", s.orgName).First(&org).Error; err != nil {
		writeErr(w, http.StatusPreconditionFailed, "organization not initialized")
		return
	}
	_ = s.engine.LoadOrgFromJSON(org.OrgJSON)
	_ = s.engine.LoadAuthFromJSON(org.AuthPubJSON, org.AuthPrvJSON)

	userattrs, err := s.engine.IssueUserKey(req.User, req.Attribute)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"userAttrsJson": abeengine.SerializeUserAttrs(userattrs),
	})
}

func (s *Server) verifyUser(req issueKeyReq) error {
	if s.caCert != "" {
		if err := msp.VerifyCertByCA(req.CertPEM, s.caCert); err != nil {
			return err
		}
	}
	if err := verifyRequestHash(req.User, req.Attribute, req.BodyHash); err != nil {
		return err
	}
	return verifySignature(req.CertPEM, req.BodyHash, req.Signature)
}

func verifySignature(certPEM, bodyHashB64, sigB64 string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return apperr.ErrUnauthorized
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return apperr.Wrap(apperr.ErrUnauthorized, "parse cert", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return apperr.ErrUnauthorized
	}
	bodyHash, err := base64.StdEncoding.DecodeString(bodyHashB64)
	if err != nil {
		return apperr.Wrap(apperr.ErrInvalidInput, "decode body hash", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return apperr.Wrap(apperr.ErrInvalidInput, "decode signature", err)
	}
	if !ecdsa.VerifyASN1(pub, bodyHash, sig) {
		return apperr.ErrUnauthorized
	}
	return nil
}

func verifyRequestHash(user, attribute, bodyHashB64 string) error {
	expected := sha256.Sum256(canonicalIssueBody(user, attribute))
	actual, err := base64.StdEncoding.DecodeString(bodyHashB64)
	if err != nil {
		return apperr.Wrap(apperr.ErrInvalidInput, "decode body hash", err)
	}
	if string(actual) != string(expected[:]) {
		return apperr.ErrUnauthorized
	}
	return nil
}

func canonicalIssueBody(user, attribute string) []byte {
	body, _ := json.Marshal(map[string]string{"attribute": attribute, "user": user})
	return body
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// Run 供总端启动。
func Run(ctx context.Context, orgName string, port int) error {
	_ = os.Setenv("ORG_NAME", orgName)
	cfg := config.Load()
	logger.Init(cfg.LogDir, cfg.LogLevel)
	if _, err := db.Init(cfg.DBPath); err != nil {
		return err
	}
	s := newServer(orgName, port, cfg)
	_ = s.bootstrapOrg()
	srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: s.handler()}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	return srv.ListenAndServe()
}
