package controller

import (
	"errors"
	"net/http"

	"bc_abe_uc/dto"
	"bc_abe/utils/apperr"
	"bc_abe/utils/logger"

	"github.com/gin-gonic/gin"
)

var ctrlLog = logger.New("controller")

func ok(ctx *gin.Context, data any) {
	ctx.JSON(http.StatusOK, dto.APIResponse{Code: 0, Data: data})
}

func fail(ctx *gin.Context, code int, err error) {
	path := ctx.FullPath()
	if path == "" {
		path = ctx.Request.URL.Path
	}
	ctrlLog.Error("%s %s -> %d: %v", ctx.Request.Method, path, code, err)
	ctx.JSON(code, dto.APIResponse{
		Code:    code,
		Message: publicMessage(err),
	})
}

func publicMessage(err error) string {
	if err == nil {
		return "unknown error"
	}
	// 保留完整链路，便于开发阶段定位 fabric-ca / gateway 等问题
	return err.Error()
}

func httpStatus(err error) int {
	switch {
	case errors.Is(err, apperr.ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, apperr.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, apperr.ErrInvalidInput):
		return http.StatusConflict
	case errors.Is(err, apperr.ErrFabricNetwork), errors.Is(err, apperr.ErrGatewayConnect):
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}
