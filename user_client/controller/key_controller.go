package controller

import (
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
		bindFail(ctx, err)
		return
	}
	result, err := c.svc.RequestKey(req.UserID, req.Attribute)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, result)
}

func (c *KeyController) AutoRequest(ctx *gin.Context) {
	var req dto.AutoKeyRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		bindFail(ctx, err)
		return
	}
	results, err := c.svc.RequestAutoKeys(req.UserID, req.Location, req.AtTime, req.Hour, req.HourOp)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, gin.H{"issued": results})
}

func (c *KeyController) List(ctx *gin.Context) {
	var req struct {
		UserID uint `form:"userId" binding:"required"`
	}
	if err := ctx.ShouldBindQuery(&req); err != nil {
		bindFail(ctx, err)
		return
	}
	keys, err := c.svc.ListUserKeys(req.UserID)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, keys)
}
