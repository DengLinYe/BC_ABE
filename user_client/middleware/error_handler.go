package middleware

import (
	"net/http"

	"bc_abe_uc/dto"

	"github.com/gin-gonic/gin"
)

// ErrorHandler 统一错误响应中间件。
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) == 0 {
			return
		}
		err := c.Errors.Last().Err
		c.JSON(http.StatusInternalServerError, dto.APIResponse{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		})
	}
}
