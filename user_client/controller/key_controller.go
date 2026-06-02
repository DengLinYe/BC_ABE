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
	result, err := c.svc.RequestKey(req.UserID, req.Attribute)
	if err != nil {
		fail(ctx, httpStatus(err), err)
		return
	}
	ok(ctx, result)
}

func (c *KeyController) AutoRequest(ctx *gin.Context) {
	var req dto.AutoKeyRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		fail(ctx, http.StatusBadRequest, err)
		return
	}
	results, err := c.svc.RequestAutoKeys(req.UserID, req.Location, req.AtTime, req.Hour, req.HourOp)
	if err != nil {
		fail(ctx, httpStatus(err), err)
		return
	}
	ok(ctx, gin.H{"issued": results})
}
