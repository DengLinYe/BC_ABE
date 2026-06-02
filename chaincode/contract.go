package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	keyGlobalParams = "GLOBAL_PARAMS"
)

// GlobalParams 链上 ABE 全局公共参数。
type GlobalParams struct {
	ID         string            `json:"id"`
	Version    int               `json:"version"`
	Curve      string            `json:"curve"`
	OrgPubKeys map[string]string `json:"orgPubKeys"`
	UpdatedAt  string            `json:"updatedAt"`
}

// CiphertextAsset 链上 ABE 密文资产。
type CiphertextAsset struct {
	ID         string `json:"id"`
	Version    int    `json:"version"`
	Policy     string `json:"policy"`
	Ciphertext string `json:"ciphertext"`
	Owner      string `json:"owner"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`
}

// ABELedger 智能合约入口。
type ABELedger struct {
	contractapi.Contract
}

func (c *ABELedger) isAdmin(ctx contractapi.TransactionContextInterface) (bool, error) {
	id := ctx.GetClientIdentity()
	cert, err := id.GetX509Certificate()
	if err != nil {
		return false, fmt.Errorf("read cert: %w", err)
	}
	mspID, err := id.GetMSPID()
	if err != nil {
		return false, fmt.Errorf("read msp id: %w", err)
	}
	if mspID != "Org1MSP" && mspID != "Org2MSP" {
		return false, nil
	}
	cn := strings.ToLower(cert.Subject.CommonName)
	if strings.Contains(cn, "admin") {
		return true, nil
	}
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.EqualFold(ou, "admin") {
			return true, nil
		}
	}
	return false, nil
}

// PutGlobalParams 写入或更新全局参数，仅 Admin MSP 可操作。
func (c *ABELedger) PutGlobalParams(ctx contractapi.TransactionContextInterface, paramsJSON string) error {
	ok, err := c.isAdmin(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("permission denied: admin msp required")
	}

	var incoming GlobalParams
	if err := json.Unmarshal([]byte(paramsJSON), &incoming); err != nil {
		return fmt.Errorf("invalid params json: %w", err)
	}
	if incoming.ID == "" {
		incoming.ID = keyGlobalParams
	}

	existingBytes, err := ctx.GetStub().GetState(keyGlobalParams)
	if err != nil {
		return fmt.Errorf("get global params: %w", err)
	}
	if existingBytes != nil {
		var existing GlobalParams
		if err := json.Unmarshal(existingBytes, &existing); err != nil {
			return fmt.Errorf("decode existing params: %w", err)
		}
		incoming.Version = existing.Version + 1
	} else {
		incoming.Version = 1
	}

	payload, err := json.Marshal(incoming)
	if err != nil {
		return fmt.Errorf("marshal params: %w", err)
	}
	return ctx.GetStub().PutState(keyGlobalParams, payload)
}

// GetGlobalParams 读取全局参数。
func (c *ABELedger) GetGlobalParams(ctx contractapi.TransactionContextInterface) (*GlobalParams, error) {
	bytes, err := ctx.GetStub().GetState(keyGlobalParams)
	if err != nil {
		return nil, fmt.Errorf("get global params: %w", err)
	}
	if bytes == nil {
		return nil, fmt.Errorf("global params not found")
	}
	var params GlobalParams
	if err := json.Unmarshal(bytes, &params); err != nil {
		return nil, fmt.Errorf("decode params: %w", err)
	}
	return &params, nil
}

// PutCiphertext 写入或更新密文资产，不鉴权。
func (c *ABELedger) PutCiphertext(ctx contractapi.TransactionContextInterface, assetJSON string) error {
	var incoming CiphertextAsset
	if err := json.Unmarshal([]byte(assetJSON), &incoming); err != nil {
		return fmt.Errorf("invalid asset json: %w", err)
	}
	if incoming.ID == "" {
		return fmt.Errorf("asset id required")
	}

	key := ciphertextKey(incoming.ID)
	existingBytes, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("get ciphertext: %w", err)
	}
	if existingBytes != nil {
		var existing CiphertextAsset
		if err := json.Unmarshal(existingBytes, &existing); err != nil {
			return fmt.Errorf("decode existing asset: %w", err)
		}
		incoming.Version = existing.Version + 1
		if incoming.CreatedAt == "" {
			incoming.CreatedAt = existing.CreatedAt
		}
	} else {
		incoming.Version = 1
	}

	payload, err := json.Marshal(incoming)
	if err != nil {
		return fmt.Errorf("marshal asset: %w", err)
	}
	return ctx.GetStub().PutState(key, payload)
}

// GetCiphertext 按 ID 读取密文资产。
func (c *ABELedger) GetCiphertext(ctx contractapi.TransactionContextInterface, id string) (*CiphertextAsset, error) {
	bytes, err := ctx.GetStub().GetState(ciphertextKey(id))
	if err != nil {
		return nil, fmt.Errorf("get ciphertext: %w", err)
	}
	if bytes == nil {
		return nil, fmt.Errorf("ciphertext %s not found", id)
	}
	var asset CiphertextAsset
	if err := json.Unmarshal(bytes, &asset); err != nil {
		return nil, fmt.Errorf("decode asset: %w", err)
	}
	return &asset, nil
}

// DeleteCiphertext 删除密文资产。
func (c *ABELedger) DeleteCiphertext(ctx contractapi.TransactionContextInterface, id string) error {
	return ctx.GetStub().DelState(ciphertextKey(id))
}

// GetEvaluateTransactions 只读查询（避免被当作 submit 且便于 Gateway evaluate）。
func (c *ABELedger) GetEvaluateTransactions() []string {
	return []string{
		"GetGlobalParams",
		"GetCiphertext",
		"ListCiphertextIDs",
	}
}

// ListCiphertextIDs 列出所有密文 ID（JSON 数组字符串；直接返回 []string 会导致 CCAAS 链码进程崩溃）。
func (c *ABELedger) ListCiphertextIDs(ctx contractapi.TransactionContextInterface) (string, error) {
	// 结束键必须是合法 UTF-8；`CT::\xff` 会在 shim 序列化 range 结果时触发 panic。
	iter, err := ctx.GetStub().GetStateByRange("CT::", "CT;")
	if err != nil {
		return "", fmt.Errorf("range query: %w", err)
	}
	defer iter.Close()

	var ids []string
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return "", fmt.Errorf("iterate: %w", err)
		}
		ids = append(ids, trimCiphertextKey(kv.Key))
	}
	payload, err := json.Marshal(ids)
	if err != nil {
		return "", fmt.Errorf("marshal ids: %w", err)
	}
	return string(payload), nil
}

func ciphertextKey(id string) string {
	return "CT::" + id
}

func trimCiphertextKey(key string) string {
	const prefix = "CT::"
	if len(key) > len(prefix) {
		return key[len(prefix):]
	}
	return key
}
