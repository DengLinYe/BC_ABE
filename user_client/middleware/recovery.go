package middleware

import (
	"io"
	"net/http"

	"bc_abe_uc/dto"

	"github.com/gin-gonic/gin"
)

// SafeRecovery 捕获 panic，返回简短 JSON，不打印堆栈。
func SafeRecovery() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, _ any) {
		c.AbortWithStatusJSON(http.StatusBadRequest, dto.APIResponse{
			Code:    http.StatusBadRequest,
			Message: "request failed",
		})
	})
}
