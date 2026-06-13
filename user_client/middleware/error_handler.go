package middleware

import (
	"bc_abe/utils/apperr"
	"bc_abe/utils/logger"
	"bc_abe_uc/dto"

	"github.com/gin-gonic/gin"
)

var errLog = logger.New("middleware")

// ErrorHandler 统一错误响应中间件。
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) == 0 {
			return
		}
		err := c.Errors.Last().Err
		code := apperr.HTTPStatus(err)
		errLog.Error("%s %s -> %d: %v", c.Request.Method, c.Request.URL.Path, code, err)
		c.JSON(code, dto.APIResponse{
			Code:    code,
			Message: apperr.PublicMessage(err),
		})
	}
}
