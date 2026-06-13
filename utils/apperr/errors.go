package apperr

import (
	"errors"
	"fmt"
	"os"
)

var (
	ErrNotFound       = errors.New("resource not found")
	ErrUnauthorized   = errors.New("unauthorized")
	ErrInvalidInput   = errors.New("invalid input")
	ErrInvalidPolicy  = errors.New("invalid policy")
	ErrDBConnect      = errors.New("database connection failed")
	ErrGatewayConnect = errors.New("fabric gateway connection failed")
	ErrFabricNetwork  = errors.New("fabric network operation failed")
	ErrConfig         = errors.New("configuration error")
)

// Wrap 包装底层错误。
func Wrap(kind error, msg string, err error) error {
	if err == nil {
		return fmt.Errorf("%w: %s", kind, msg)
	}
	return fmt.Errorf("%w: %s: %v", kind, msg, err)
}

// Is 判断错误类型。
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// ExitOn 记录错误并退出进程（替代 main 中的 panic）。
func ExitOn(log interface{ Error(string, ...any) }, err error) {
	if err == nil {
		return
	}
	log.Error("%v", err)
	os.Exit(1)
}
