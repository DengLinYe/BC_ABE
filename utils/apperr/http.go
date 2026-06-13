package apperr

import (
	"errors"
	"net/http"
)

const (
	MsgInternal     = "internal server error"
	MsgBadRequest   = "bad request"
	MsgUnauthorized = "unauthorized"
	MsgNotFound     = "not found"
	MsgUnavailable  = "service unavailable"
	MsgInvalidPolicy = "invalid policy"
)

// PublicMessage 返回可安全展示给客户端的简短文案（不含内部细节）。
func PublicMessage(err error) string {
	if err == nil {
		return MsgInternal
	}
	switch {
	case Is(err, ErrUnauthorized):
		return MsgUnauthorized
	case Is(err, ErrNotFound):
		return MsgNotFound
	case Is(err, ErrInvalidPolicy):
		return MsgInvalidPolicy
	case Is(err, ErrInvalidInput):
		return MsgBadRequest
	case Is(err, ErrFabricNetwork), Is(err, ErrGatewayConnect):
		return MsgUnavailable
	default:
		return MsgInternal
	}
}

// HTTPStatus 根据错误类型映射 HTTP 状态码。
func HTTPStatus(err error) int {
	switch {
	case Is(err, ErrUnauthorized):
		return http.StatusUnauthorized
	case Is(err, ErrNotFound):
		return http.StatusNotFound
	case Is(err, ErrInvalidInput), Is(err, ErrInvalidPolicy):
		return http.StatusBadRequest
	case Is(err, ErrFabricNetwork), Is(err, ErrGatewayConnect):
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// IsClientError 是否为 4xx 类业务错误（非 panic / 未知错误）。
func IsClientError(err error) bool {
	code := HTTPStatus(err)
	return code >= 400 && code < 500
}

// UnwrapKind 供日志使用，保留 errors.Is 链。
func UnwrapKind(err error) error {
	if err == nil {
		return nil
	}
	for _, k := range []error{
		ErrUnauthorized, ErrNotFound, ErrInvalidInput, ErrInvalidPolicy,
		ErrFabricNetwork, ErrGatewayConnect, ErrDBConnect, ErrConfig,
	} {
		if Is(err, k) {
			return k
		}
	}
	return errors.New("unknown")
}
