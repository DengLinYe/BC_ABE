package db

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"bc_abe/utils/apperr"
	"bc_abe/utils/config"
	"bc_abe/utils/logger"

	_ "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

var (
	instance *gorm.DB
	mu       sync.Mutex
	log      = logger.New("db").SilentConsole()
)

// Init 初始化 MySQL 单例：自动建库、AutoMigrate。
func Init(cfg config.Config) (*gorm.DB, error) {
	mu.Lock()
	defer mu.Unlock()
	if instance != nil {
		return instance, nil
	}
	dsn := strings.TrimSpace(cfg.MySQLDSN)
	if dsn == "" {
		return nil, apperr.Wrap(apperr.ErrDBConnect, "open mysql", fmt.Errorf("MYSQL_DSN is empty"))
	}
	if err := ensureDatabase(dsn); err != nil {
		return nil, apperr.Wrap(apperr.ErrDBConnect, "ensure database", err)
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		return nil, apperr.Wrap(apperr.ErrDBConnect, "open mysql", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, apperr.Wrap(apperr.ErrDBConnect, "get sql db", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(time.Hour)
	if err := db.AutoMigrate(&Organization{}, &UserAccount{}, &UserABEKey{}); err != nil {
		return nil, apperr.Wrap(apperr.ErrDBConnect, "auto migrate", err)
	}
	if err := ensureLongTextColumns(db); err != nil {
		return nil, apperr.Wrap(apperr.ErrDBConnect, "ensure column types", err)
	}
	instance = db
	log.Info("database initialized")
	return instance, nil
}

// Reset 删除并重建 MySQL 库，用于完整清理回到 0 状态。
func Reset(cfg config.Config) error {
	dsn := strings.TrimSpace(cfg.MySQLDSN)
	if dsn == "" {
		return apperr.Wrap(apperr.ErrDBConnect, "reset mysql", fmt.Errorf("MYSQL_DSN is empty"))
	}
	serverDSN, dbName, err := parseDSN(dsn)
	if err != nil {
		return apperr.Wrap(apperr.ErrDBConnect, "reset mysql", err)
	}
	conn, err := sql.Open("mysql", serverDSN)
	if err != nil {
		return apperr.Wrap(apperr.ErrDBConnect, "reset mysql", err)
	}
	defer conn.Close()
	if err := conn.Ping(); err != nil {
		return apperr.Wrap(apperr.ErrDBConnect, "reset mysql ping", err)
	}
	quoted := quoteIdent(dbName)
	if _, err := conn.Exec("DROP DATABASE IF EXISTS " + quoted); err != nil {
		return apperr.Wrap(apperr.ErrDBConnect, "drop database", err)
	}
	if _, err := conn.Exec("CREATE DATABASE " + quoted + " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		return apperr.Wrap(apperr.ErrDBConnect, "create database", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if instance != nil {
		if sqlDB, err := instance.DB(); err == nil {
			_ = sqlDB.Close()
		}
		instance = nil
	}
	log.Info("database reset: %s", dbName)
	return nil
}

func ensureDatabase(dsn string) error {
	serverDSN, dbName, err := parseDSN(dsn)
	if err != nil {
		return err
	}
	conn, err := sql.Open("mysql", serverDSN)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Ping(); err != nil {
		return err
	}
	quoted := quoteIdent(dbName)
	_, err = conn.Exec("CREATE DATABASE IF NOT EXISTS " + quoted + " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
	return err
}

func parseDSN(dsn string) (serverDSN, dbName string, err error) {
	qIdx := strings.Index(dsn, "?")
	base, query := dsn, ""
	if qIdx >= 0 {
		base, query = dsn[:qIdx], dsn[qIdx:]
	}
	slash := strings.LastIndex(base, "/")
	if slash < 0 {
		return "", "", fmt.Errorf("invalid MYSQL_DSN: missing database name")
	}
	dbName = strings.TrimSpace(base[slash+1:])
	if dbName == "" {
		return "", "", fmt.Errorf("invalid MYSQL_DSN: empty database name")
	}
	serverDSN = base[:slash+1]
	if query != "" {
		serverDSN += query
	} else {
		serverDSN += "?charset=utf8mb4&parseTime=True&loc=Local"
	}
	return serverDSN, dbName, nil
}

func quoteIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

func ensureLongTextColumns(db *gorm.DB) error {
	if db.Migrator().HasTable(&UserABEKey{}) {
		if err := db.Migrator().AlterColumn(&UserABEKey{}, "UserKeyJSON"); err != nil {
			return err
		}
	}
	return nil
}

// Get 返回数据库单例。
func Get() *gorm.DB {
	return instance
}

// Transaction 在事务中执行 fn。
func Transaction(fn func(tx *gorm.DB) error) error {
	return Get().Transaction(fn)
}
