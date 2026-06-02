package dto

type RegisterRequest struct {
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password" binding:"required"`
	OrgName    string `json:"orgName" binding:"required"`
	Attributes string `json:"attributes"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type EncryptRequest struct {
	UserID   uint   `json:"userId" binding:"required"`
	Filename string `json:"filename"`
	Content  string `json:"content" binding:"required"`
	Policy   string `json:"policy" binding:"required"`
}

type KeyRequest struct {
	UserID    uint   `json:"userId" binding:"required"`
	Attribute string `json:"attribute" binding:"required"`
}

type DecryptRequest struct {
	UserID  uint   `json:"userId" binding:"required"`
	AssetID string `json:"assetId" binding:"required"`
}

type APIResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}
