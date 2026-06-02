package db

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"bc_abe/utils/apperr"
	"bc_abe/utils/config"
	"bc_abe/utils/logger"
	"bc_abe/utils/msp"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var seedLog = logger.New("db/seed").SilentConsole()

type fabricUserSpec struct {
	username   string
	password   string
	orgName    string
	mspUserDir string
	attributes string
}

// SeedFabricUsers 将 network.sh 创建的 admin / user1 同步到本地数据库。
func SeedFabricUsers(cfg config.Config) error {
	if Get() == nil {
		return apperr.Wrap(apperr.ErrDBConnect, "seed fabric users", fmt.Errorf("database not initialized"))
	}
	specs := []fabricUserSpec{
		{
			username:   "admin",
			password:   "org1adminpw",
			orgName:    "org1",
			mspUserDir: "users/Admin@org1.example.com/msp",
			attributes: "admin",
		},
		{
			username:   "user1",
			password:   "user1pw",
			orgName:    "org1",
			mspUserDir: "users/User1@org1.example.com/msp",
			attributes: "member",
		},
		{
			username:   "admin",
			password:   "org2adminpw",
			orgName:    "org2",
			mspUserDir: "users/Admin@org2.example.com/msp",
			attributes: "admin",
		},
		{
			username:   "user1",
			password:   "user1pw",
			orgName:    "org2",
			mspUserDir: "users/User1@org2.example.com/msp",
			attributes: "member",
		},
	}

	var firstErr error
	for _, spec := range specs {
		if err := seedOneFabricUser(cfg, spec); err != nil {
			seedLog.Warn("seed %s@%s skipped: %v", spec.username, spec.orgName, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func seedOneFabricUser(cfg config.Config, spec fabricUserSpec) error {
	orgDomain := "org1.example.com"
	if spec.orgName == "org2" {
		orgDomain = "org2.example.com"
	}
	mspDir := filepath.Join(cfg.FabricNetworkDir, "organizations/peerOrganizations", orgDomain, spec.mspUserDir)
	if _, err := os.Stat(mspDir); err != nil {
		return apperr.Wrap(apperr.ErrNotFound, "fabric msp dir", err)
	}

	certPEM, keyPEM, err := msp.LoadIdentityFromMSP(mspDir)
	if err != nil {
		return err
	}

	dbUsername := fmt.Sprintf("%s@%s", spec.username, spec.orgName)
	var existing UserAccount
	err = Get().Where("username = ?", dbUsername).First(&existing).Error
	if err == nil {
		seedLog.Info("fabric user already seeded: %s", dbUsername)
		return nil
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return apperr.Wrap(apperr.ErrDBConnect, "query fabric user", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(spec.password), bcrypt.DefaultCost)
	if err != nil {
		return apperr.Wrap(apperr.ErrInvalidInput, "hash password", err)
	}

	user := UserAccount{
		Username:     dbUsername,
		PasswordHash: string(hash),
		OrgName:      spec.orgName,
		Attributes:   spec.attributes,
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		MSPID:        config.MSPIDForOrg(spec.orgName),
	}
	if err := Get().Create(&user).Error; err != nil {
		return apperr.Wrap(apperr.ErrDBConnect, "create fabric user", err)
	}
	seedLog.Info("seeded fabric user: %s", dbUsername)
	return nil
}
