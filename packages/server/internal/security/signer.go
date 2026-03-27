package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

const minHMACKeyLength = 32

// ErrHMACKeyRequired はHMACキーが未設定の場合のエラー
var ErrHMACKeyRequired = errors.New("HMAC key is required: set SENTINEL_HMAC_KEY environment variable (minimum 32 bytes)")

// ErrHMACKeyTooShort はHMACキーが短すぎる場合のエラー
var ErrHMACKeyTooShort = fmt.Errorf("HMAC key must be at least %d bytes", minHMACKeyLength)

// IntegritySigner はインメモリのハッシュチェーンを管理する（goroutine-safe）
type IntegritySigner struct {
	mu           sync.Mutex
	previousHash string
	hmacKey      []byte
}

// NewIntegritySigner はHMACキー付きでSignerを生成する。キーは必須（最低32 bytes）。
func NewIntegritySigner(hmacKey []byte) (*IntegritySigner, error) {
	if len(hmacKey) == 0 {
		return nil, ErrHMACKeyRequired
	}
	if len(hmacKey) < minHMACKeyLength {
		return nil, ErrHMACKeyTooShort
	}
	return &IntegritySigner{hmacKey: hmacKey}, nil
}

func (s *IntegritySigner) PreviousHash() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.previousHash
}

func (s *IntegritySigner) UpdateChain(hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.previousHash = hash
}

func (s *IntegritySigner) ResetChain() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.previousHash = ""
}

// ApplyHashChain はアトミックにpreviousHash読み取り→ハッシュ計算→チェーン更新を行う
func (s *IntegritySigner) ApplyHashChain(log *domain.Log) {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.PreviousHash = s.previousHash
	log.Hash = calculateHMAC(log, s.previousHash, s.hmacKey)
	s.previousHash = log.Hash
}

// CalculateHash はログと前のハッシュからHMAC-SHA256ハッシュを計算する
func CalculateHash(log domain.Log, previousHash string, hmacKey []byte) string {
	return calculateHMAC(&log, previousHash, hmacKey)
}

// VerifyHash はログのハッシュが正しいか検証する（constant-time comparison）
func VerifyHash(log domain.Log, expectedPreviousHash string, hmacKey []byte) bool {
	if log.Hash == "" {
		return false
	}
	computed := CalculateHash(log, expectedPreviousHash, hmacKey)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(log.Hash)) == 1
}

func calculateHMAC(log *domain.Log, previousHash string, key []byte) string {
	savedHash := log.Hash
	savedSig := log.Signature
	log.Hash = ""
	log.Signature = ""

	serialized := deterministicSerialize(*log)

	log.Hash = savedHash
	log.Signature = savedSig

	h := hmac.New(sha256.New, key)
	h.Write([]byte(serialized + previousHash))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func deterministicSerialize(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("__serialize_error:%v__", err)
	}
	var raw interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return string(b)
	}
	return sortedJSON(raw)
}

func sortedJSON(v interface{}) string {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		result := "{"
		for i, k := range keys {
			if i > 0 {
				result += ","
			}
			kJSON, _ := json.Marshal(k)
			result += string(kJSON) + ":" + sortedJSON(val[k])
		}
		result += "}"
		return result
	case []interface{}:
		result := "["
		for i, item := range val {
			if i > 0 {
				result += ","
			}
			result += sortedJSON(item)
		}
		result += "]"
		return result
	default:
		b, _ := json.Marshal(val)
		return string(b)
	}
}
