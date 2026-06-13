package controller

import (
	"bc_abe_uc/dto"
	"bc_abe_uc/service"

	"github.com/gin-gonic/gin"
)

// AuthController 认证控制器。
type AuthController struct {
	svc *service.AuthService
}

func NewAuthController(svc *service.AuthService) *AuthController {
	return &AuthController{svc: svc}
}

func (c *AuthController) Register(ctx *gin.Context) {
	var req dto.RegisterRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		bindFail(ctx, err)
		return
	}
	user, err := c.svc.Register(req.Username, req.Password, req.OrgName, req.Attributes)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, gin.H{"id": user.ID, "username": user.Username, "orgName": user.OrgName})
}

func (c *AuthController) Login(ctx *gin.Context) {
	var req dto.LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		bindFail(ctx, err)
		return
	}
	user, err := c.svc.Login(req.Username, req.Password)
	if err != nil {
		fail(ctx, err)
		return
	}
	ok(ctx, gin.H{"id": user.ID, "username": user.Username, "orgName": user.OrgName, "attributes": user.Attributes})
}
