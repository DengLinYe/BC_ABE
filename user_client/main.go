package main

import (
	"fmt"

	"bc_abe/utils/apperr"
	"bc_abe/utils/config"
	"bc_abe/utils/db"
	"bc_abe/utils/gateway"
	"bc_abe/utils/logger"
	"bc_abe_uc/routes"
)

var log = logger.New("user_client")

func main() {
	cfg := config.Load()
	logger.Init(cfg.LogDir, cfg.LogLevel)
	if _, err := db.Init(cfg.DBPath); err != nil {
		apperr.ExitOn(log, err)
	}

	if opts, err := gateway.DefaultOrg1Options(cfg.ChannelName, cfg.ChaincodeName); err == nil {
		if _, err := gateway.Init(opts); err != nil {
			log.Warn("gateway init skipped: %v", err)
		}
	}

	r := routes.NewEngine(cfg)
	addr := fmt.Sprintf(":%d", cfg.UserClientPort)
	log.Info("user client listening on %s", addr)
	if err := r.Run(addr); err != nil {
		apperr.ExitOn(log, apperr.Wrap(apperr.ErrInvalidInput, "http server", err))
	}
}
