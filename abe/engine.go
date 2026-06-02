package abe

import (
	"bc_abe/pkg/mosaic/abe"
)

// Engine 封装 mosaic ABE 核心能力。
type Engine struct {
	seed     string
	curve    abe.Curve
	org      *abe.Org
	authKeys *abe.AuthKeys
}

// NewEngine 创建 ABE 引擎实例。
func NewEngine(seed string) *Engine {
	return &Engine{seed: seed}
}

// InitOrg 初始化组织与曲线参数。
func (e *Engine) InitOrg() error {
	e.curve = abe.NewCurve().SetSeed(e.seed).InitRng()
	e.org = abe.NewRandomOrg(e.curve)
	return nil
}

// InitAuthority 初始化权威机构公私钥。
func (e *Engine) InitAuthority() error {
	if e.org == nil {
		if err := e.InitOrg(); err != nil {
			return err
		}
	}
	e.authKeys = abe.NewRandomAuth(e.org)
	return nil
}

// Org 返回当前组织。
func (e *Engine) Org() *abe.Org {
	return e.org
}

// AuthKeys 返回当前权威机构密钥。
func (e *Engine) AuthKeys() *abe.AuthKeys {
	return e.authKeys
}

// AuthPubJSON 返回权威机构公钥 JSON。
func (e *Engine) AuthPubJSON() string {
	if e.authKeys == nil {
		return ""
	}
	return abe.Encode(abe.JsonObjToStr(e.authKeys.AuthPub.ToJsonObj()))
}

// AuthPrvJSON 返回权威机构私钥 JSON。
func (e *Engine) AuthPrvJSON() string {
	if e.authKeys == nil {
		return ""
	}
	return abe.Encode(abe.JsonObjToStr(e.authKeys.AuthPrv.ToJsonObj()))
}

// OrgJSON 返回组织 JSON。
func (e *Engine) OrgJSON() string {
	if e.org == nil {
		return ""
	}
	return abe.Encode(abe.JsonObjToStr(e.org.ToJsonObj()))
}

// CurveJSON 返回曲线 JSON。
func (e *Engine) CurveJSON() string {
	if e.curve == nil {
		return ""
	}
	return abe.Encode(abe.JsonObjToStr(e.curve.ToJsonObj()))
}

// IssueUserKey 为用户按属性签发密钥。
func (e *Engine) IssueUserKey(user, attr string) (*abe.UserAttrs, error) {
	if e.authKeys == nil {
		return nil, ErrAuthorityNotInit
	}
	return abe.NewRandomUserkey(user, attr, e.authKeys.AuthPrv), nil
}

// MergeUserKeys 合并多属性用户密钥。
func (e *Engine) MergeUserKeys(base *abe.UserAttrs, extra *abe.UserAttrs) *abe.UserAttrs {
	if base == nil {
		return extra
	}
	if extra == nil {
		return base
	}
	return base.Add(extra)
}

// NewSecret 生成随机 GT 秘密点。
func (e *Engine) NewSecret() (abe.Point, error) {
	if e.org == nil {
		return nil, ErrOrgNotInit
	}
	return abe.NewRandomSecret(e.org), nil
}

// Encrypt 按策略加密秘密。
func (e *Engine) Encrypt(secret abe.Point, policy string, authpubs *abe.AuthPubs) (*abe.Ciphertext, error) {
	return abe.Encrypt(secret, policy, authpubs), nil
}

// Decrypt 解密密文；会先按策略重算系数（可重复调用）。
func (e *Engine) Decrypt(ct *abe.Ciphertext, userattrs *abe.UserAttrs) (abe.Point, error) {
	if ct == nil || userattrs == nil {
		return nil, ErrDecryptInput
	}
	userattrs.SelectUserAttrs(userattrs.User, ct.Policy)
	if err := validateDecryptInputs(ct, userattrs); err != nil {
		return nil, err
	}
	return abe.Decrypt(ct, userattrs), nil
}

func validateDecryptInputs(ct *abe.Ciphertext, userattrs *abe.UserAttrs) error {
	for attr, cs := range userattrs.Coeff {
		rows, ok := ct.C[attr]
		if !ok {
			continue
		}
		for k, coeff := range cs {
			if coeff != 0 && k >= len(rows) {
				return ErrDecryptInput
			}
		}
	}
	return nil
}

// AuthPubsOfPolicy 从策略提取所需 authority 公钥槽位。
func (e *Engine) AuthPubsOfPolicy(policy string) *abe.AuthPubs {
	return abe.AuthPubsOfPolicy(policy)
}

// FillAuthPub 将本地 authority 公钥填入 authpubs。
func (e *Engine) FillAuthPub(authpubs *abe.AuthPubs, authName string) {
	if e.authKeys == nil || authpubs == nil {
		return
	}
	if authpubs.AuthPub == nil {
		authpubs.AuthPub = make(map[string]*abe.AuthPub)
	}
	authpubs.AuthPub[authName] = e.authKeys.AuthPub
}

// SecretHash 计算 secret 哈希。
func (e *Engine) SecretHash(secret abe.Point) string {
	return abe.SecretHash(secret)
}

// LoadOrgFromJSON 从 JSON 恢复组织。
func (e *Engine) LoadOrgFromJSON(orgJSON string) error {
	e.org = abe.NewOrgOfJsonStr(orgJSON).OfJsonObj()
	if e.org != nil {
		e.curve = e.org.Crv
	}
	return nil
}

// LoadAuthFromJSON 从 JSON 恢复 authority 密钥。
func (e *Engine) LoadAuthFromJSON(authPubJSON, authPrvJSON string) error {
	pub := abe.NewAuthPubOfJsonStr(authPubJSON).OfJsonObj()
	prv := abe.NewAuthPrvOfJsonStr(authPrvJSON).OfJsonObj()
	e.authKeys = &abe.AuthKeys{AuthPub: pub, AuthPrv: prv}
	return nil
}

// ParseAuthPub 解析 authority 公钥 JSON。
func ParseAuthPub(authPubJSON string) *abe.AuthPub {
	return abe.NewAuthPubOfJsonStr(authPubJSON).OfJsonObj()
}

// SerializeOrg 序列化组织参数，用于校验 ciphertext/authpub 是否属于同一组织。
func SerializeOrg(org *abe.Org) string {
	if org == nil {
		return ""
	}
	return abe.Encode(abe.JsonObjToStr(org.ToJsonObj()))
}

// ParseCiphertext 解析密文 JSON。
func ParseCiphertext(ctJSON string) *abe.Ciphertext {
	return abe.NewCiphertextOfJsonStr(ctJSON).OfJsonObj()
}

// ParseUserAttrs 解析用户属性 JSON。
func ParseUserAttrs(jsonStr string) *abe.UserAttrs {
	return abe.NewUserAttrsOfJsonStr(jsonStr).OfJsonObj()
}

// SerializeCiphertext 序列化密文。
func SerializeCiphertext(ct *abe.Ciphertext) string {
	return abe.Encode(abe.JsonObjToStr(ct.ToJsonObj()))
}

// SerializeUserAttrs 序列化用户属性。
func SerializeUserAttrs(userattrs *abe.UserAttrs) string {
	return abe.Encode(abe.JsonObjToStr(userattrs.ToJsonObj()))
}
