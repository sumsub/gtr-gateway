package gtr

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type testVectors struct {
	KeyPairs struct {
		Gateway struct {
			PrivateKey string `json:"privateKey"`
			PublicKey  string `json:"publicKey"`
		} `json:"gateway"`
		Counterparty struct {
			PublicKey string `json:"publicKey"`
		} `json:"counterparty"`
	} `json:"keyPairs"`
	Vectors []struct {
		Payload          string `json:"payload"`
		Signature        string `json:"signature"`
		EncryptedPayload string `json:"encryptedPayload"`
	} `json:"vectors"`
}

func loadVectors(t *testing.T) testVectors {
	t.Helper()
	data, err := os.ReadFile("../../test-vectors/crypto-box.json")
	if err != nil {
		t.Fatalf("cannot read test vectors: %v", err)
	}
	var vectors testVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("cannot parse test vectors: %v", err)
	}
	return vectors
}

func TestKeyParsing(t *testing.T) {
	vectors := loadVectors(t)
	gateway, err := ParseEd25519PrivateKey(vectors.KeyPairs.Gateway.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := PublicKeyBase64(gateway); got != vectors.KeyPairs.Gateway.PublicKey {
		t.Errorf("public key from 64-byte key: got %s, want %s", got, vectors.KeyPairs.Gateway.PublicKey)
	}

	secretKey, _ := base64.StdEncoding.DecodeString(vectors.KeyPairs.Gateway.PrivateKey)
	fromSeed, err := ParseEd25519PrivateKey(base64.StdEncoding.EncodeToString(secretKey[:32]))
	if err != nil {
		t.Fatal(err)
	}
	if PublicKeyBase64(fromSeed) != vectors.KeyPairs.Gateway.PublicKey {
		t.Error("public key from 32-byte seed differs")
	}
}

func TestReferenceVectors(t *testing.T) {
	vectors := loadVectors(t)
	gateway, err := ParseEd25519PrivateKey(vectors.KeyPairs.Gateway.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	counterparty, err := ParseEd25519PublicKey(vectors.KeyPairs.Counterparty.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, vector := range vectors.Vectors {
		t.Run(vector.Payload, func(t *testing.T) {
			decrypted, err := DecryptPayload(vector.EncryptedPayload, gateway, counterparty)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if string(decrypted) != vector.Payload {
				t.Errorf("decrypt: got %q, want %q", decrypted, vector.Payload)
			}

			encrypted, err := EncryptPayload([]byte(vector.Payload), gateway, counterparty)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if encrypted == vector.EncryptedPayload {
				t.Error("encrypt must use a fresh nonce")
			}
			roundTrip, err := DecryptPayload(encrypted, gateway, counterparty)
			if err != nil || string(roundTrip) != vector.Payload {
				t.Errorf("round trip: got %q, %v", roundTrip, err)
			}

			if got := SignPayload([]byte(vector.Payload), gateway); got != vector.Signature {
				t.Errorf("signature: got %s, want %s", got, vector.Signature)
			}
			if !VerifyPayloadSignature(vector.Signature, []byte(vector.Payload), gateway.PublicKey) {
				t.Error("reference signature must verify")
			}
		})
	}
}

func TestDecryptRejectsTamperedPacket(t *testing.T) {
	vectors := loadVectors(t)
	gateway, _ := ParseEd25519PrivateKey(vectors.KeyPairs.Gateway.PrivateKey)
	counterparty, _ := ParseEd25519PublicKey(vectors.KeyPairs.Counterparty.PublicKey)

	packet, _ := base64.StdEncoding.DecodeString(vectors.Vectors[2].EncryptedPayload)
	packet[len(packet)-1] ^= 0x01
	_, err := DecryptPayload(base64.StdEncoding.EncodeToString(packet), gateway, counterparty)
	var cryptoErr *CryptoError
	if !errors.As(err, &cryptoErr) || !strings.Contains(err.Error(), "cannot be decrypted") {
		t.Errorf("expected a CryptoError about decryption, got %v", err)
	}
}

func TestRejectsKeysOfWrongLength(t *testing.T) {
	if _, err := ParseEd25519PrivateKey(base64.StdEncoding.EncodeToString(make([]byte, 31))); err == nil {
		t.Error("31-byte private key must be rejected")
	}
	if _, err := ParseEd25519PublicKey(base64.StdEncoding.EncodeToString(make([]byte, 33))); err == nil {
		t.Error("33-byte public key must be rejected")
	}
	if _, err := ParseEd25519PublicKey("not base64!"); err == nil {
		t.Error("invalid base64 must be rejected")
	}
}
