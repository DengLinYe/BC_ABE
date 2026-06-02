package abe

import mosaic "bc_abe/pkg/mosaic/abe"

type (
	Point      = mosaic.Point
	Curve      = mosaic.Curve
	Org        = mosaic.Org
	AuthPub    = mosaic.AuthPub
	AuthPrv    = mosaic.AuthPrv
	AuthKeys   = mosaic.AuthKeys
	AuthPubs   = mosaic.AuthPubs
	Userkey    = mosaic.Userkey
	UserAttrs  = mosaic.UserAttrs
	Ciphertext = mosaic.Ciphertext
)

// SelectUserAttrs 为策略选择用户属性系数。
func SelectUserAttrs(userattrs *UserAttrs, user, policy string) *UserAttrs {
	return userattrs.SelectUserAttrs(user, policy)
}
