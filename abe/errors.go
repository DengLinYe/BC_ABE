package abe

import "errors"

var (
	ErrOrgNotInit       = errors.New("abe: organization not initialized")
	ErrAuthorityNotInit = errors.New("abe: authority not initialized")
	ErrDecryptInput     = errors.New("abe: decrypt inputs do not match policy or user keys")
	ErrInvalidPolicy    = errors.New("abe: invalid policy syntax")
)
