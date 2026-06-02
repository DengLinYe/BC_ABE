package routes

import (
	abeengine "bc_abe/abe"
	"bc_abe/utils/config"
	"bc_abe/utils/pathutil"
	"bc_abe_uc/controller"
	"bc_abe_uc/middleware"
	"bc_abe_uc/service"

	"github.com/gin-gonic/gin"
)

// NewEngine 创建并配置 Gin 引擎。
func NewEngine(cfg config.Config) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.AccessLog())
	r.Use(middleware.ErrorHandler())
	Register(r, cfg)
	return r
}

// Register 注册路由（洋葱模型：middleware -> controller -> service）。
func Register(r *gin.Engine, cfg config.Config) {
	engine := abeengine.NewEngine(cfg.ABESeed)

	authSvc := service.NewAuthService()
	fileSvc := service.NewFileService(cfg, engine)
	keySvc := service.NewKeyService(cfg, engine)

	authCtrl := controller.NewAuthController(authSvc)
	fileCtrl := controller.NewFileController(fileSvc)
	keyCtrl := controller.NewKeyController(keySvc)

	staticDir := pathutil.Abs("./user_client/static")
	r.Static("/static", staticDir)
	r.GET("/", func(c *gin.Context) { c.File(staticDir + "/index.html") })

	api := r.Group("/api/v1")
	{
		api.POST("/register", authCtrl.Register)
		api.POST("/login", authCtrl.Login)
		api.POST("/files/encrypt", fileCtrl.Encrypt)
		api.POST("/files/decrypt", fileCtrl.Decrypt)
		api.POST("/keys/request", keyCtrl.Request)
	}
}
