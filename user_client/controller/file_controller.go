package controller

import (
	"net/http"

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
		fail(ctx, http.StatusBadRequest, err)
		return
	}
	result, err := c.svc.Encrypt(req.UserID, req.Filename, req.Content, req.Policy)
	if err != nil {
		fail(ctx, httpStatus(err), err)
		return
	}
	ok(ctx, result)
}

func (c *FileController) Decrypt(ctx *gin.Context) {
	var req dto.DecryptRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		fail(ctx, http.StatusBadRequest, err)
		return
	}
	result, err := c.svc.Decrypt(req.UserID, req.AssetID)
	if err != nil {
		fail(ctx, httpStatus(err), err)
		return
	}
	ok(ctx, result)
}
