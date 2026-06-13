package controller

import (
	"bc_abe/utils/apperr"
	"bc_abe/utils/logger"
	"bc_abe_uc/dto"

	"github.com/gin-gonic/gin"
)

var ctrlLog = logger.New("controller")

func ok(ctx *gin.Context, data any) {
	ctx.JSON(200, dto.APIResponse{Code: 0, Data: data})
}

func bindFail(ctx *gin.Context, err error) {
	fail(ctx, apperr.Wrap(apperr.ErrInvalidInput, "request", err))
}

func fail(ctx *gin.Context, err error) {
	code := apperr.HTTPStatus(err)
	path := ctx.FullPath()
	if path == "" {
		path = ctx.Request.URL.Path
	}
	ctrlLog.Error("%s %s -> %d: %v", ctx.Request.Method, path, code, err)
	ctx.JSON(code, dto.APIResponse{
		Code:    code,
		Message: apperr.PublicMessage(err),
	})
}
