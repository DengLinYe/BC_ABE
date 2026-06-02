package db

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"bc_abe/utils/apperr"
	"bc_abe/utils/logger"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

var (
	instance *gorm.DB
	once     sync.Once
	log      = logger.New("db").SilentConsole()
)

// Init 初始化 SQLite 单例连接。
func Init(dbPath string) (*gorm.DB, error) {
	var initErr error
	once.Do(func() {
		if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
			initErr = apperr.Wrap(apperr.ErrDBConnect, "mkdir db dir", err)
			return
		}
		db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
			Logger: gormlogger.Default.LogMode(gormlogger.Warn),
		})
		if err != nil {
			initErr = apperr.Wrap(apperr.ErrDBConnect, "open sqlite", err)
			return
		}
		sqlDB, err := db.DB()
		if err != nil {
			initErr = apperr.Wrap(apperr.ErrDBConnect, "get sql db", err)
			return
		}
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetConnMaxLifetime(time.Hour)
		if err := autoMigrateLocked(dbPath, db); err != nil {
			initErr = err
			return
		}
		instance = db
		log.Info("database initialized: %s", dbPath)
	})
	return instance, initErr
}

func autoMigrateLocked(dbPath string, db *gorm.DB) error {
	lockPath := dbPath + ".migrate.lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return apperr.Wrap(apperr.ErrDBConnect, "open migrate lock", err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return apperr.Wrap(apperr.ErrDBConnect, "acquire migrate lock", err)
	}
	defer func() { _ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) }()

	if err := db.AutoMigrate(&Organization{}, &UserAccount{}, &UserABEKey{}); err != nil {
		if isTableExistsErr(err) && tablesReady(db) {
			log.Info("database schema already up to date")
			return nil
		}
		return apperr.Wrap(apperr.ErrDBConnect, "auto migrate", err)
	}
	return nil
}

func isTableExistsErr(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists")
}

func tablesReady(db *gorm.DB) bool {
	m := db.Migrator()
	return m.HasTable(&Organization{}) && m.HasTable(&UserAccount{}) && m.HasTable(&UserABEKey{})
}

// Get 返回数据库单例。
func Get() *gorm.DB {
	return instance
}
