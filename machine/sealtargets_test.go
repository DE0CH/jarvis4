package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

// a kernel machine's write: secrets signs no store key, so the machine computes P + K from the phone secrets' signed
// state names and secrets' agreement key from the roster; ✱ a state another key signed
func TestAKernelWriterComputesTheStoreKey(t *testing.T) {
	sec, _ := sig.NewSigner()
	phone, _ := ecdh.P256().GenerateKey(rand.Reader)
	agree, _ := ecdh.P256().GenerateKey(rand.Reader)
	pa, ka := sig.B64.EncodeToString(phone.PublicKey().Bytes()), sig.B64.EncodeToString(agree.PublicKey().Bytes())
	state, _ := sec.SignJSON(map[string]any{"kind": "secrets-state", "master": "M", "phone": map[string]string{"signingKey": "S", "agreementKey": pa}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"identity": map[string]any{"signingKey": sec.PublicKey(), "state": state}})
	}))
	defer srv.Close()
	c := &client{base: srv.URL, me: "m1", http: srv.Client()}
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	c.sig = k
	storeKey, master, err := sealTargets(c, sec.PublicKey(), ka)
	want, _ := sig.StoreKey(pa, ka)
	if err != nil || storeKey != want || master != "M" {
		t.Fatal(err, storeKey, master)
	}
	other, _ := sig.NewSigner()
	if _, _, err := sealTargets(c, other.PublicKey(), ka); err == nil {
		t.Fatal("a state another key signed was taken")
	}
}
