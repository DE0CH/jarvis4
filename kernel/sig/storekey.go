package sig

import (
	"fmt"

	"filippo.io/nistec"
)

// StoreKey: the store key C = P + K, what every writer wraps a key's data key to — the phone's agreement key P plus
// secrets' agreement key K (both base64 X9.63; the answer too). Each writer computes it from keys it already trusts
// (secrets' signed state names P, the roster names K): secrets signs no store key.
func StoreKey(phone, secrets string) (string, error) {
	pb, err := B64.DecodeString(phone)
	if err != nil {
		return "", fmt.Errorf("the phone's agreement key: %v", err)
	}
	kb, err := B64.DecodeString(secrets)
	if err != nil {
		return "", fmt.Errorf("secrets' agreement key: %v", err)
	}
	p, err := nistec.NewP256Point().SetBytes(pb)
	if err != nil {
		return "", fmt.Errorf("the phone's agreement key: %v", err)
	}
	k, err := nistec.NewP256Point().SetBytes(kb)
	if err != nil {
		return "", fmt.Errorf("secrets' agreement key: %v", err)
	}
	c := nistec.NewP256Point().Add(p, k).Bytes()
	if len(c) != 65 {
		return "", fmt.Errorf("P + K is the point at infinity")
	}
	return B64.EncodeToString(c), nil
}
