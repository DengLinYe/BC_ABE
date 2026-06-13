package controller

import (
	"bc_abe_uc/dto"
	"bc_abe_uc/service"

	"github.com/gin-gonic/gin"
)

// FileController 文件加解密控制器。
type FileController struct {
	svc *service.FileService
}

func NewFileController(svc *service.FileService) *FileController {
	return &FileController{svc: svc}
}

func (c *FileController) Encrypt(ctx *gin.Context) {
	var req dto.EncryptRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		bindFail(ctx, err)
		return
	}
	result, err := c.svc.Encrypt(req.UserID, req.Filename, req.Content, req.Policy)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, result)
}

func (c *FileController) Update(ctx *gin.Context) {
	var req struct {
		UserID  uint   `json:"userId" binding:"required"`
		AssetID string `json:"assetId" binding:"required"`
		Content string `json:"content" binding:"required"`
		Policy  string `json:"policy" binding:"required"`
	}
	if err := ctx.ShouldBindJSON(&req); err != nil {
		bindFail(ctx, err)
		return
	}
	result, err := c.svc.Update(req.UserID, req.AssetID, req.Content, req.Policy)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, result)
}

func (c *FileController) List(ctx *gin.Context) {
	var req struct {
		UserID    uint `form:"userId" binding:"required"`
		OwnedOnly bool `form:"ownedOnly"`
	}
	if err := ctx.ShouldBindQuery(&req); err != nil {
		bindFail(ctx, err)
		return
	}
	files, err := c.svc.List(req.UserID, req.OwnedOnly)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, files)
}

func (c *FileController) Delete(ctx *gin.Context) {
	var req dto.DeleteFileRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		bindFail(ctx, err)
		return
	}
	if err := c.svc.Delete(req.UserID, req.AssetID); err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, gin.H{"deleted": req.AssetID})
}

func (c *FileController) Decrypt(ctx *gin.Context) {
	var req dto.DecryptRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		bindFail(ctx, err)
		return
	}
	result, err := c.svc.Decrypt(req.UserID, req.AssetID)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, result)
}
