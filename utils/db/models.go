package db

import "time"

// Organization 组织及其 ABE 私钥管理。
type Organization struct {
	ID           uint   `gorm:"primaryKey"`
	Name         string `gorm:"uniqueIndex;size:64"`
	MSPID        string `gorm:"size:64"`
	AuthName     string `gorm:"size:64"`
	OrgJSON      string `gorm:"type:text"`
	AuthPubJSON  string `gorm:"type:text"`
	AuthPrvJSON  string `gorm:"type:text"`
	CurveJSON    string `gorm:"type:text"`
	AdminCertPEM string `gorm:"type:text"`
	AdminKeyPEM  string `gorm:"type:text"`
	CACertPEM    string `gorm:"type:text"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserAccount 用户账号与 Fabric 证书私钥。
type UserAccount struct {
	ID           uint   `gorm:"primaryKey"`
	Username     string `gorm:"uniqueIndex;size:128"`
	PasswordHash string `gorm:"size:256"`
	OrgName      string `gorm:"size:64;index"`
	Attributes   string `gorm:"type:text"`
	CertPEM      string `gorm:"type:text"`
	KeyPEM       string `gorm:"type:text"`
	MSPID        string `gorm:"size:64"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserABEKey 用户 ABE 属性密钥（可多版本）。
type UserABEKey struct {
	ID          uint   `gorm:"primaryKey"`
	UserID      uint   `gorm:"index"`
	Attribute   string `gorm:"size:128;index"`
	Version     int
	UserKeyJSON string `gorm:"type:longtext"`
	CreatedAt   time.Time
}
