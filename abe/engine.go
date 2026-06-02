package abe

import (
	"fmt"
	"regexp"
	"strings"

	mosaic "bc_abe/pkg/mosaic/abe"
)

// 对外暴露的 mosaic 类型（避免业务层直接依赖 pkg/mosaic/abe）。
type (
	UserAttrs  = mosaic.UserAttrs
	Userkey    = mosaic.Userkey
	Ciphertext = mosaic.Ciphertext
)

var (
	reHourSingleEq  = regexp.MustCompile(`(?i)(hour@[a-zA-Z0-9_]+)\s*=\s*(\d+)`)
	rePolicyAnd     = regexp.MustCompile(`(?i)\s+and\s+`)
	rePolicyOr      = regexp.MustCompile(`(?i)\s+or\s+`)
	reLocUnderscore = regexp.MustCompile(`(?i)loc_(school|home|others)@`)
)

// NormalizePolicySyntax 修正 UI/旧数据里不符合 ABE 语法的片段。
func NormalizePolicySyntax(policy string) string {
	p := strings.TrimSpace(policy)
	p = reHourSingleEq.ReplaceAllString(p, "${1} == ${2}")
	p = rePolicyAnd.ReplaceAllString(p, " /\\ ")
	p = rePolicyOr.ReplaceAllString(p, " \\/ ")
	p = reLocUnderscore.ReplaceAllString(p, "loc$1@")
	return strings.TrimSpace(p)
}

// Engine 封装 mosaic ABE 核心能力。
type Engine struct {
	seed     string
	curve    mosaic.Curve
	org      *mosaic.Org
	authKeys *mosaic.AuthKeys
}

// NewEngine 创建 ABE 引擎实例。
func NewEngine(seed string) *Engine {
	return &Engine{seed: seed}
}

// InitOrg 初始化组织与曲线参数。
func (e *Engine) InitOrg() error {
	e.curve = mosaic.NewCurve().SetSeed(e.seed).InitRng()
	e.org = mosaic.NewRandomOrg(e.curve)
	return nil
}

// InitAuthority 初始化权威机构公私钥。
func (e *Engine) InitAuthority() error {
	if e.org == nil {
		if err := e.InitOrg(); err != nil {
			return err
		}
	}
	e.authKeys = mosaic.NewRandomAuth(e.org)
	return nil
}

// Org 返回当前组织。
func (e *Engine) Org() *mosaic.Org {
	return e.org
}

// AuthKeys 返回当前权威机构密钥。
func (e *Engine) AuthKeys() *mosaic.AuthKeys {
	return e.authKeys
}

// AuthPubJSON 返回权威机构公钥 JSON。
func (e *Engine) AuthPubJSON() string {
	if e.authKeys == nil {
		return ""
	}
	return mosaic.Encode(mosaic.JsonObjToStr(e.authKeys.AuthPub.ToJsonObj()))
}

// AuthPrvJSON 返回权威机构私钥 JSON。
func (e *Engine) AuthPrvJSON() string {
	if e.authKeys == nil {
		return ""
	}
	return mosaic.Encode(mosaic.JsonObjToStr(e.authKeys.AuthPrv.ToJsonObj()))
}

// OrgJSON 返回组织 JSON。
func (e *Engine) OrgJSON() string {
	if e.org == nil {
		return ""
	}
	return mosaic.Encode(mosaic.JsonObjToStr(e.org.ToJsonObj()))
}

// CurveJSON 返回曲线 JSON。
func (e *Engine) CurveJSON() string {
	if e.curve == nil {
		return ""
	}
	return mosaic.Encode(mosaic.JsonObjToStr(e.curve.ToJsonObj()))
}

// IssueUserKey 为用户按属性签发密钥。
func (e *Engine) IssueUserKey(user, attr string) (*mosaic.UserAttrs, error) {
	if e.authKeys == nil {
		return nil, ErrAuthorityNotInit
	}
	return mosaic.NewRandomUserkey(user, attr, e.authKeys.AuthPrv), nil
}

// NewEmptyUserAttrs 返回无密钥的用户属性容器。
func NewEmptyUserAttrs(user string) *UserAttrs {
	return &UserAttrs{
		User:    user,
		Coeff:   map[string][]int{},
		Userkey: map[string]*Userkey{},
	}
}

// MergeUserKeys 合并多属性用户密钥。
func (e *Engine) MergeUserKeys(base, extra *UserAttrs) *UserAttrs {
	if base == nil {
		return extra
	}
	if extra == nil {
		return base
	}
	return base.Add(extra)
}

// NewSecret 生成随机 GT 秘密点。
func (e *Engine) NewSecret() (mosaic.Point, error) {
	if e.org == nil {
		return nil, ErrOrgNotInit
	}
	return mosaic.NewRandomSecret(e.org), nil
}

// Encrypt 按策略加密秘密。
func (e *Engine) Encrypt(secret mosaic.Point, policy string, authpubs *mosaic.AuthPubs) (*mosaic.Ciphertext, error) {
	policy = NormalizePolicySyntax(policy)
	if len(mosaic.AuthPubsOfPolicy(policy).AuthPub) == 0 {
		return nil, ErrInvalidPolicy
	}
	if authpubs == nil || len(authpubs.AuthPub) == 0 {
		return nil, fmt.Errorf("%w: missing authority keys", ErrInvalidPolicy)
	}
	org := mosaic.GetOrgFromAuthPubs(authpubs)
	if org == nil || org.Crv == nil {
		return nil, fmt.Errorf("%w: authority org not loaded", ErrInvalidPolicy)
	}
	return mosaic.Encrypt(secret, policy, authpubs), nil
}

// Decrypt 解密密文；会先按策略重算系数（可重复调用）。
func (e *Engine) Decrypt(ct *mosaic.Ciphertext, userattrs *mosaic.UserAttrs) (mosaic.Point, error) {
	if ct == nil || userattrs == nil {
		return nil, ErrDecryptInput
	}
	userattrs.SelectUserAttrs(userattrs.User, NormalizePolicySyntax(ct.Policy))
	if err := validateDecryptInputs(ct, userattrs); err != nil {
		return nil, err
	}
	return mosaic.Decrypt(ct, userattrs), nil
}

func validateDecryptInputs(ct *mosaic.Ciphertext, userattrs *mosaic.UserAttrs) error {
	for attr, cs := range userattrs.Coeff {
		rows, ok := ct.C[attr]
		for k, coeff := range cs {
			if coeff == 0 {
				continue
			}
			if !ok || k >= len(rows) || len(rows[k]) < 4 {
				return ErrDecryptInput
			}
		}
	}
	return nil
}

// AuthPubsOfPolicy 从策略提取所需 authority 公钥槽位。
func (e *Engine) AuthPubsOfPolicy(policy string) *mosaic.AuthPubs {
	return mosaic.AuthPubsOfPolicy(NormalizePolicySyntax(policy))
}

// FillAuthPub 将本地 authority 公钥填入 authpubs。
func (e *Engine) FillAuthPub(authpubs *mosaic.AuthPubs, authName string) {
	if e.authKeys == nil || authpubs == nil {
		return
	}
	if authpubs.AuthPub == nil {
		authpubs.AuthPub = make(map[string]*mosaic.AuthPub)
	}
	authpubs.AuthPub[authName] = e.authKeys.AuthPub
}

// SecretHash 计算 secret 哈希。
func (e *Engine) SecretHash(secret mosaic.Point) string {
	return mosaic.SecretHash(secret)
}

// LoadOrgFromJSON 从 JSON 恢复组织。
func (e *Engine) LoadOrgFromJSON(orgJSON string) error {
	e.org = mosaic.NewOrgOfJsonStr(orgJSON).OfJsonObj()
	if e.org != nil {
		e.curve = e.org.Crv
	}
	return nil
}

// LoadAuthFromJSON 从 JSON 恢复 authority 密钥。
func (e *Engine) LoadAuthFromJSON(authPubJSON, authPrvJSON string) error {
	pub := mosaic.NewAuthPubOfJsonStr(authPubJSON).OfJsonObj()
	prv := mosaic.NewAuthPrvOfJsonStr(authPrvJSON).OfJsonObj()
	e.authKeys = &mosaic.AuthKeys{AuthPub: pub, AuthPrv: prv}
	return nil
}

// ParseAuthPub 解析 authority 公钥 JSON。
func ParseAuthPub(authPubJSON string) *mosaic.AuthPub {
	return mosaic.NewAuthPubOfJsonStr(authPubJSON).OfJsonObj()
}

// SerializeOrg 序列化组织参数，用于校验 ciphertext/authpub 是否属于同一组织。
func SerializeOrg(org *mosaic.Org) string {
	if org == nil {
		return ""
	}
	return mosaic.Encode(mosaic.JsonObjToStr(org.ToJsonObj()))
}

// ParseCiphertext 解析密文 JSON。
func ParseCiphertext(ctJSON string) *mosaic.Ciphertext {
	return mosaic.NewCiphertextOfJsonStr(ctJSON).OfJsonObj()
}

// ParseUserAttrs 解析用户属性 JSON。
func ParseUserAttrs(jsonStr string) *mosaic.UserAttrs {
	return mosaic.NewUserAttrsOfJsonStr(jsonStr).OfJsonObj()
}

// SerializeCiphertext 序列化密文。
func SerializeCiphertext(ct *mosaic.Ciphertext) string {
	return mosaic.Encode(mosaic.JsonObjToStr(ct.ToJsonObj()))
}

// SerializeUserAttrs 序列化用户属性。
func SerializeUserAttrs(userattrs *mosaic.UserAttrs) string {
	return mosaic.Encode(mosaic.JsonObjToStr(userattrs.ToJsonObj()))
}
