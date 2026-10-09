package gtr

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/nacl/box"
)

const nonceSize = 24

// KeyPair is the gateway's Ed25519 identity registered with GTR.
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// CryptoError reports a key or payload that cannot be processed; the gateway answers 422.
type CryptoError struct {
	Message string
	Err     error
}

func (e *CryptoError) Error() string { return e.Message }
func (e *CryptoError) Unwrap() error { return e.Err }

// ParseEd25519PrivateKey accepts the 32-byte seed or the 64-byte libsodium secret key
// (seed followed by public key), which is also Go's ed25519.PrivateKey layout.
func ParseEd25519PrivateKey(base64Value string) (KeyPair, error) {
	raw, err := fromBase64(base64Value)
	if err != nil {
		return KeyPair{}, err
	}
	var private ed25519.PrivateKey
	switch len(raw) {
	case ed25519.SeedSize:
		private = ed25519.NewKeyFromSeed(raw)
	case ed25519.PrivateKeySize:
		private = ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	default:
		return KeyPair{}, &CryptoError{Message: fmt.Sprintf(
			"Ed25519 private key must be %d or %d bytes, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))}
	}
	return KeyPair{PublicKey: private.Public().(ed25519.PublicKey), PrivateKey: private}, nil
}

// ParseEd25519PublicKey decodes a base64 Ed25519 public key.
func ParseEd25519PublicKey(base64Value string) (ed25519.PublicKey, error) {
	raw, err := fromBase64(base64Value)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, &CryptoError{Message: fmt.Sprintf("Ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))}
	}
	return ed25519.PublicKey(raw), nil
}

// PublicKeyBase64 is the value sent to GTR as initiatorPublicKey.
func PublicKeyBase64(keyPair KeyPair) string {
	return base64.StdEncoding.EncodeToString(keyPair.PublicKey)
}

// EncryptPayload builds the GTR PII envelope: NaCl crypto_box between the two VASPs' Ed25519
// identities converted to X25519, encoded as base64(nonce[24] || mac[16] || ciphertext).
func EncryptPayload(plaintext []byte, own KeyPair, counterparty ed25519.PublicKey) (string, error) {
	peer, err := toCurvePublicKey(counterparty)
	if err != nil {
		return "", err
	}
	private := toCurvePrivateKey(own)

	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", &CryptoError{Message: "cannot generate a nonce", Err: err}
	}
	packet := box.Seal(nonce[:], plaintext, &nonce, &peer, &private)
	return base64.StdEncoding.EncodeToString(packet), nil
}

// DecryptPayload is the mirror image of EncryptPayload.
func DecryptPayload(packetBase64 string, own KeyPair, counterparty ed25519.PublicKey) ([]byte, error) {
	packet, err := fromBase64(packetBase64)
	if err != nil {
		return nil, err
	}
	if len(packet) < nonceSize+box.Overhead {
		return nil, &CryptoError{Message: "encrypted payload is too short"}
	}
	peer, err := toCurvePublicKey(counterparty)
	if err != nil {
		return nil, err
	}
	private := toCurvePrivateKey(own)

	var nonce [nonceSize]byte
	copy(nonce[:], packet[:nonceSize])
	plaintext, ok := box.Open(nil, packet[nonceSize:], &nonce, &peer, &private)
	if !ok {
		return nil, &CryptoError{Message: "encrypted payload cannot be decrypted"}
	}
	return plaintext, nil
}

// SignPayload returns the base64 Ed25519 detached signature of data.
func SignPayload(data []byte, own KeyPair) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(own.PrivateKey, data))
}

// VerifyPayloadSignature checks a base64 Ed25519 detached signature.
func VerifyPayloadSignature(signatureBase64 string, data []byte, publicKey ed25519.PublicKey) bool {
	signature, err := fromBase64(signatureBase64)
	if err != nil {
		return false
	}
	return ed25519.Verify(publicKey, data, signature)
}

// toCurvePrivateKey mirrors libsodium's crypto_sign_ed25519_sk_to_curve25519: the clamped
// first half of SHA-512(seed) is the X25519 scalar.
func toCurvePrivateKey(own KeyPair) [32]byte {
	digest := sha512.Sum512(own.PrivateKey.Seed())
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64
	var out [32]byte
	copy(out[:], digest[:32])
	return out
}

// toCurvePublicKey mirrors libsodium's crypto_sign_ed25519_pk_to_curve25519.
func toCurvePublicKey(publicKey ed25519.PublicKey) ([32]byte, error) {
	var out [32]byte
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return out, &CryptoError{Message: "counterparty public key is not a valid Ed25519 key", Err: err}
	}
	copy(out[:], point.BytesMontgomery())
	return out, nil
}

func fromBase64(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, &CryptoError{Message: "value is not valid base64", Err: err}
	}
	return raw, nil
}
