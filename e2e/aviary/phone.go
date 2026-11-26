package main

// The phone's documents and crypto as the iPhone makes them (ios/Security/CoreCrypto.swift), written here rather than
// taken from the kernel: the driver plays the phone, so its side is an implementation of its own the kernel
// (rust/kernel, rust/sig) must agree with. Keys and points are base64 X9.63 P-256, signatures base64 DER ECDSA over
// SHA-256.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"filippo.io/nistec"
)

// signDoc: a signed document {payload, sig}
type signDoc struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

// identity: a kernel component's keys
type identity struct {
	Role         string `json:"role"`
	SigningKey   string `json:"signingKey"`
	AgreementKey string `json:"agreementKey"`
}

// roster: the root key's roster as the router takes it (members sorted by role)
type roster struct {
	Kind    string     `json:"kind"`
	Copy    string     `json:"copy"`
	Members []identity `json:"members"`
}

// cert: the part of a succession cert the driver reads
type cert struct {
	Source *struct {
		Image string `json:"image"`
	} `json:"source"`
}

type signer struct{ key *ecdsa.PrivateKey }

func newSigner() (*signer, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &signer{k}, nil
}

// signerFromPEM: a PKCS#8 P-256 private key
func signerFromPEM(b []byte) (*signer, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 key")
	}
	return &signer{ek}, nil
}

func (s *signer) Sign(payload []byte) (string, error) {
	h := sha256.Sum256(payload)
	b, err := ecdsa.SignASN1(rand.Reader, s.key, h[:])
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(b), nil
}

func (s *signer) PublicKey() string {
	b, _ := s.key.PublicKey.ECDH()
	return b64.EncodeToString(b.Bytes())
}

// sealedDoc: AES-GCM(nonce || ciphertext) under HKDF-SHA256(x(e·R), info), e the ephemeral key
type sealedDoc struct {
	E    string `json:"e"`
	Data string `json:"data"`
}

func sealTo(recipient string, plain []byte, info string) (sealedDoc, error) {
	rb, err := b64.DecodeString(recipient)
	if err != nil {
		return sealedDoc{}, err
	}
	r, err := ecdh.P256().NewPublicKey(rb)
	if err != nil {
		return sealedDoc{}, err
	}
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	x, err := e.ECDH(r)
	if err != nil {
		return sealedDoc{}, err
	}
	k, _ := hkdf.Key(sha256.New, x, nil, info, 32)
	return sealedDoc{E: b64.EncodeToString(e.PublicKey().Bytes()), Data: b64.EncodeToString(gcmSeal(k, plain, nil))}, nil
}

// addPoints: P + Q, uncompressed
func addPoints(a, b []byte) ([]byte, error) {
	p, err := nistec.NewP256Point().SetBytes(a)
	if err != nil {
		return nil, err
	}
	q, err := nistec.NewP256Point().SetBytes(b)
	if err != nil {
		return nil, err
	}
	return nistec.NewP256Point().Add(p, q).Bytes(), nil
}

// scalarMult: k·P, uncompressed
func scalarMult(k, raw []byte) ([]byte, error) {
	p, err := nistec.NewP256Point().SetBytes(raw)
	if err != nil {
		return nil, err
	}
	r, err := nistec.NewP256Point().ScalarMult(p, k)
	if err != nil {
		return nil, err
	}
	return r.Bytes(), nil
}

// a store key as the app writes it: the value under its own data key, AAD store "\n" key; that data key wrapped to
// P + K under HKDF(x(e·(P+K)), "jarvis2/store-data-key")
type wrappedKey struct {
	E       string `json:"e"`
	Wrapped string `json:"wrapped"`
}

type keyEntry struct {
	Store   string     `json:"store"`
	Key     string     `json:"key"`
	Wrapped wrappedKey `json:"wrapped"`
	Data    string     `json:"data"`
}

func keyAAD(store, key string) []byte { return []byte(store + "\n" + key) }

func gcmSeal(key, plain, aad []byte) []byte {
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	nonce := randBytes(g.NonceSize())
	return append(nonce, g.Seal(nil, nonce, plain, aad)...)
}
