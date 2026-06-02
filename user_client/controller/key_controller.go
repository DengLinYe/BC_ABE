package controller

import (
	"net/http"

	"bc_abe_uc/dto"
	"bc_abe_uc/service"

	"github.com/gin-gonic/gin"
)

// KeyController 密钥申请控制器。
type KeyController struct {
	svc *service.KeyService
}

func NewKeyController(svc *service.KeyService) *KeyController {
	return &KeyController{svc: svc}
}

func (c *KeyController) Request(ctx *gin.Context) {
	var req dto.KeyRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		fail(ctx, http.StatusBadRequest, err)
		return
	}
	count, err := c.svc.RequestKey(req.UserID, req.Attribute)
	if err != nil {
		fail(ctx, httpStatus(err), err)
		return
	}
	ok(ctx, gin.H{"attribute": req.Attribute, "keys": count})
}
