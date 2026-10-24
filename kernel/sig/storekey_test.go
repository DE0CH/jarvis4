package sig

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

// P + K is the curve's sum (against crypto/elliptic's own Add), in either order; ✱ a key that isn't a point
func TestStoreKey(t *testing.T) {
	p, _ := ecdh.P256().GenerateKey(rand.Reader)
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	pb, kb := p.PublicKey().Bytes(), k.PublicKey().Bytes()
	c, err := StoreKey(B64.EncodeToString(pb), B64.EncodeToString(kb))
	if err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.P256().Add(new(big.Int).SetBytes(pb[1:33]), new(big.Int).SetBytes(pb[33:]), new(big.Int).SetBytes(kb[1:33]), new(big.Int).SetBytes(kb[33:])) //nolint:staticcheck // the reference
	want := make([]byte, 65)
	want[0] = 4
	x.FillBytes(want[1:33])
	y.FillBytes(want[33:])
	if c != B64.EncodeToString(want) {
		t.Fatal("P + K isn't the curve's sum")
	}
	if c2, _ := StoreKey(B64.EncodeToString(kb), B64.EncodeToString(pb)); c2 != c {
		t.Fatal("not symmetric")
	}
	if _, err := StoreKey("AAAA", B64.EncodeToString(kb)); err == nil {
		t.Fatal("a phone key that isn't a point")
	}
}
