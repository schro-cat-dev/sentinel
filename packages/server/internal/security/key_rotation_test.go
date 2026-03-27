package security

import (
	"testing"

	"github.com/schro-cat-dev/sentinel-server/testutil"
)

func TestKeyRotation_VerifyWithCurrentKey(t *testing.T) {
	s := mustSigner(t)
	log := testutil.NewTestLog()
	s.ApplyHashChain(&log)

	if !s.VerifyHashWithRotation(log, "") {
		t.Error("should verify with current key")
	}
}

func TestKeyRotation_VerifyWithPreviousKey(t *testing.T) {
	oldKey := []byte("old-hmac-key-that-is-32-bytes-!!")
	newKey := []byte("new-hmac-key-that-is-32-bytes-!!")

	// 旧キーでハッシュ生成
	oldSigner, _ := NewIntegritySigner(oldKey)
	log := testutil.NewTestLog()
	oldSigner.ApplyHashChain(&log)

	// 新キーのSignerに旧キーを追加
	newSigner, _ := NewIntegritySigner(newKey)
	newSigner.AddPreviousKey(oldKey)

	// 旧キーで生成されたハッシュを新Signerで検証
	if !newSigner.VerifyHashWithRotation(log, "") {
		t.Error("should verify with previous key after rotation")
	}
}

func TestKeyRotation_FailWithUnknownKey(t *testing.T) {
	s := mustSigner(t)
	log := testutil.NewTestLog()

	// 別のキーでハッシュ生成
	otherKey := []byte("other-key-that-is-32-bytes-long!")
	otherSigner, _ := NewIntegritySigner(otherKey)
	otherSigner.ApplyHashChain(&log)

	// 現在のキーでも旧キーでもないキーで生成 → 検証失敗
	if s.VerifyHashWithRotation(log, "") {
		t.Error("should fail with unknown key")
	}
}

func TestKeyRotation_MultiplePreviousKeys(t *testing.T) {
	key1 := []byte("key-v1-that-is-32-bytes-long-!!x")
	key2 := []byte("key-v2-that-is-32-bytes-long-!!x")
	key3 := []byte("key-v3-that-is-32-bytes-long-!!x")

	// v1でハッシュ生成
	signer1, _ := NewIntegritySigner(key1)
	log := testutil.NewTestLog()
	signer1.ApplyHashChain(&log)

	// v3 (current) に v1, v2 を旧キーとして追加
	signer3, _ := NewIntegritySigner(key3)
	signer3.AddPreviousKey(key1)
	signer3.AddPreviousKey(key2)

	if !signer3.VerifyHashWithRotation(log, "") {
		t.Error("should verify with v1 key from v3 signer")
	}
}
