package middleware

import (
	"time"

	"bc_abe/utils/logger"

	"github.com/gin-gonic/gin"
)

var accessLog = logger.New("http")

// AccessLog 记录 API 请求；4xx/5xx 额外打 WARN 便于排查。
func AccessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		status := c.Writer.Status()
		latency := time.Since(start)
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		if status >= 500 {
			accessLog.Error("%s %s %d %s", c.Request.Method, path, status, latency)
		} else if status >= 400 {
			accessLog.Warn("%s %s %d %s", c.Request.Method, path, status, latency)
		} else if path != "/" && path != "/static/*filepath" {
			accessLog.Info("%s %s %d %s", c.Request.Method, path, status, latency)
		}
	}
}
