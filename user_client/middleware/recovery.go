package middleware

import (
	"io"
	"net/http"

	"bc_abe/utils/apperr"
	"bc_abe/utils/logger"
	"bc_abe_uc/dto"

	"github.com/gin-gonic/gin"
)

var recoveryLog = logger.New("recovery")

// SafeRecovery 捕获 panic：详情写日志，对外仅返回通用 500。
func SafeRecovery() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, err any) {
		recoveryLog.Error("%s %s panic: %v", c.Request.Method, c.Request.URL.Path, err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, dto.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: apperr.MsgInternal,
		})
	})
}
