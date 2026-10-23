package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/secrets"
)

// what put-key sends opens exactly as the core (with the combined store key's scalar) and Deyao's kit (with the master
// key) open it, and the signature covers the core's WriterText
func TestPutKeySealsToTheStoreAndTheMasterKey(t *testing.T) {
	combined, _ := ecdh.P256().GenerateKey(rand.Reader) // stands for p + k (the phone's and the core's shares)
	master, _ := ecdh.P256().GenerateKey(rand.Reader)
	sig, _ := ecdh.P256().GenerateKey(rand.Reader)
	pub := func(k *ecdh.PrivateKey) string { return b64.EncodeToString(k.PublicKey().Bytes()) }
	req, err := keyWriteRequest(pub(combined), pub(master), sig, "yyc", "YYC_KEY", []byte("v4lue"), false, "the cluster's key")
	if err != nil {
		t.Fatal(err)
	}
	w := req["wrapped"].(map[string]string)
	dk, err := openSealed(combined, w["e"], w["wrapped"], "jarvis2/store-data-key")
	if err != nil {
		t.Fatal("the data key isn't wrapped to the store key:", err)
	}
	data, _ := b64.DecodeString(req["data"].(string))
	if v, err := gcmOpenAAD(dk, data, []byte("yyc\nYYC_KEY")); err != nil || string(v) != "v4lue" {
		t.Fatalf("the value doesn't open under its store and key: %q %v", v, err)
	}
	if _, err := gcmOpenAAD(dk, data, []byte("yyc\nOTHER")); err == nil {
		t.Fatal("the value opened under another key's name")
	}
	bk := req["backup"].(map[string]string)
	bd, _ := b64.DecodeString(bk["data"])
	x, _ := master.ECDH(mustPub(t, bk["e"]))
	if v, err := gcmOpenAAD(hkdfKey(t, x, "jarvis2/backup"), bd, []byte("yyc\nYYC_KEY")); err != nil || string(v) != "v4lue" {
		t.Fatalf("the backup doesn't open with the master key: %v", err)
	}
	h := sha256.Sum256([]byte(bk["e"] + "\n" + bk["data"]))
	if req["backupSha256"] != hex.EncodeToString(h[:]) {
		t.Fatal("backupSha256 isn't the backup's")
	}
	if !verify(pub(sig), []byte(writerText("yyc", "YYC_KEY", w["e"], req["data"].(string), req["backupSha256"].(string))), req["sig"].(string)) {
		t.Fatal("the signature doesn't cover WriterText")
	}
	// a delete: no value, no backup, still signed
	del, _ := keyWriteRequest(pub(combined), pub(master), sig, "yyc", "YYC_KEY", nil, true, "")
	if del["wrapped"] != nil || del["backup"] != nil || !verify(pub(sig), []byte(writerText("yyc", "YYC_KEY", "", "", "")), del["sig"].(string)) {
		t.Fatalf("delete %v", del)
	}
}

func gcmOpenAAD(key, sealed, aad []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	if len(sealed) < g.NonceSize()+g.Overhead() {
		return nil, errShort
	}
	return g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], aad)
}

var errShort = errors.New("short")

func mustPub(t *testing.T, s string) *ecdh.PublicKey {
	b, _ := b64.DecodeString(s)
	k, err := ecdh.P256().NewPublicKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func hkdfKey(t *testing.T, x []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, x, nil, info, 32)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// a kernel machine's live copy opens in secrets exactly as kernel/secrets liveUpdate opens it (its agreement key, the
// store's and the key's names in the info)
func TestTheLiveCopyOpensInSecrets(t *testing.T) {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	e, data, err := sealParts(b64.EncodeToString(k.PublicKey().Bytes()), []byte("v4lue"), liveInfo("yyc", "YYC_KEY"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := secrets.OpenSealed(k, secrets.Sealed{E: e, Data: data}, "jarvis2/live-key\nyyc\nYYC_KEY"); err != nil || string(v) != "v4lue" {
		t.Fatalf("secrets can't open the live copy: %q %v", v, err)
	}
}
