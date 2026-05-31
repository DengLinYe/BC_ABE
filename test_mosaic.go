package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"

	"bc_abe/pkg/mosaic/abe"
)

// 从 ABE 的 GT 秘密点派生出一个稳定的 256 位对称密钥。
// 同一个秘密点序列化后的字节一致，因此加解密两端能得到相同的密钥。
func deriveSymmetricKey(secret abe.Point) [32]byte {
	return sha256.Sum256([]byte(secret.ToJsonObj().GetP()))
}

// 用 AES-256-GCM 加密文档（演示“用 secret 对称加密真实数据”这一步）。
func aesEncrypt(key [32]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// 用 AES-256-GCM 解密文档。
func aesDecrypt(key [32]byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, body := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, body, nil)
}

// 给某个用户按属性列表分发密钥，合并成一份 UserAttrs。
func issueUserKeys(user string, attrs []string, authprv *abe.AuthPrv) *abe.UserAttrs {
	var userattrs *abe.UserAttrs
	for _, attr := range attrs {
		ua := abe.NewRandomUserkey(user, attr, authprv)
		if userattrs == nil {
			userattrs = ua
		} else {
			userattrs.Add(ua)
		}
	}
	return userattrs
}

func main() {
	fmt.Println("================ ABE 全流程演示 (miracl / BN254) ================")

	// --------------------------------------------------------------------
	// 1. 初始化：建立曲线、组织(Org)、权威机构(Authority)
	// --------------------------------------------------------------------
	fmt.Println("\n[1] 初始化 organization 与 authority ...")
	curve := abe.NewCurve().SetSeed("mosaic-demo-seed").InitRng()
	org := abe.NewRandomOrg(curve)
	authkeys := abe.NewRandomAuth(org)
	fmt.Println("    - 曲线/组织已建立")
	fmt.Println("    - 权威机构 auth0 的公私钥已生成 (authpub / authprv)")

	// --------------------------------------------------------------------
	// 2. 用户密钥分发：authority 给用户颁发属性密钥
	// --------------------------------------------------------------------
	fmt.Println("\n[2] 用户密钥分发 ...")
	alice := "alice@example.com"
	aliceAttrs := []string{"A@auth0", "B@auth0", "C@auth0"} // Alice 拥有 A、B、C
	aliceKeys := issueUserKeys(alice, aliceAttrs, authkeys.AuthPrv)
	fmt.Printf("    - 已为 %s 颁发属性密钥: %v\n", alice, aliceAttrs)

	bob := "bob@example.com"
	bobAttrs := []string{"A@auth0"} // Bob 只有 A，属性不足
	bobKeys := issueUserKeys(bob, bobAttrs, authkeys.AuthPrv)
	fmt.Printf("    - 已为 %s 颁发属性密钥: %v\n", bob, bobAttrs)

	// --------------------------------------------------------------------
	// 3. 数据加密
	//    - 生成随机 secret (GT 上的点)
	//    - 用 secret 派生对称密钥, AES-GCM 加密真实文档
	//    - 用 ABE 按访问策略加密 secret
	// --------------------------------------------------------------------
	fmt.Println("\n[3] 数据加密 ...")
	policy := `A@auth0 /\ (B@auth0 /\ (C@auth0 \/ D@auth0))`
	fmt.Printf("    - 访问策略: %s\n", policy)

	document := []byte("这是一份机密文档：ABE 多授权密文策略加密演示。")

	secret := abe.NewRandomSecret(org)
	secretHash := abe.SecretHash(secret)

	symKey := deriveSymmetricKey(secret)
	encDoc, err := aesEncrypt(symKey, document)
	if err != nil {
		log.Fatalf("文档对称加密失败: %v", err)
	}
	fmt.Printf("    - 文档已用 secret 派生的密钥做 AES-256-GCM 加密 (%d 字节密文)\n", len(encDoc))

	// 收集策略涉及的 authority 公钥, 然后 ABE 加密 secret
	authpubs := abe.AuthPubsOfPolicy(policy)
	for authName := range authpubs.AuthPub {
		authpubs.AuthPub[authName] = authkeys.AuthPub
	}
	ct := abe.Encrypt(secret, policy, authpubs)
	fmt.Println("    - secret 已用 ABE 按策略加密为密文 (Ciphertext)")
	fmt.Printf("    - 密文中嵌入的策略: %s\n", abe.PolicyOfCiphertext(ct))

	// --------------------------------------------------------------------
	// 4. 数据解密 (Alice: 属性满足策略)
	// --------------------------------------------------------------------
	fmt.Println("\n[4] 数据解密 —— Alice (拥有 A,B,C, 满足策略) ...")
	aliceKeys.SelectUserAttrs(alice, policy) // 选出对该策略有用的属性并计算系数
	recovered := abe.Decrypt(ct, aliceKeys)

	if abe.SecretHash(recovered) == secretHash {
		fmt.Println("    - ABE 解密成功: 恢复出的 secret 与原始 secret 一致 (hash 校验通过)")
		recKey := deriveSymmetricKey(recovered)
		decDoc, err := aesDecrypt(recKey, encDoc)
		if err != nil {
			log.Fatalf("文档对称解密失败: %v", err)
		}
		if bytes.Equal(decDoc, document) {
			fmt.Printf("    - 文档解密成功, 明文: %s\n", string(decDoc))
		} else {
			fmt.Println("    - [异常] 文档解密结果与原文不一致")
		}
	} else {
		fmt.Println("    - [异常] Alice 应该能解密, 但 secret 校验失败")
	}

	// --------------------------------------------------------------------
	// 5. 反例 (Bob: 属性不满足策略, 应当无法恢复 secret)
	// --------------------------------------------------------------------
	fmt.Println("\n[5] 数据解密 —— Bob (只有 A, 不满足策略) ...")
	bobKeys.SelectUserAttrs(bob, policy)
	recovered2 := abe.Decrypt(ct, bobKeys)
	if abe.SecretHash(recovered2) == secretHash {
		fmt.Println("    - [异常] Bob 不应当能恢复 secret")
	} else {
		fmt.Println("    - 符合预期: Bob 属性不足, 无法恢复 secret (hash 校验不通过)")
	}

	fmt.Println("\n================ 演示结束 ================")
}
