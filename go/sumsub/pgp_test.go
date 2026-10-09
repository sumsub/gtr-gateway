package sumsub

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

type pgpVectors struct {
	SignedAt int64 `json:"signedAt"`
	Keys     struct {
		Sumsub  struct{ PublicKey string }  `json:"sumsub"`
		Gateway struct{ PrivateKey string } `json:"gateway"`
	} `json:"keys"`
	Plaintext string `json:"plaintext"`
	Messages  []struct {
		Name    string `json:"name"`
		Expect  string `json:"expect"`
		Message string `json:"message"`
	} `json:"messages"`
	Digest struct {
		Message   string `json:"message"`
		SecretKey string `json:"secretKey"`
		Algorithm string `json:"algorithm"`
		Timestamp string `json:"timestamp"`
		Value     string `json:"value"`
	} `json:"digest"`
}

func loadPGPVectors(t *testing.T) pgpVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", "pgp.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors pgpVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func (v pgpVectors) message(t *testing.T, name string) string {
	t.Helper()
	for _, candidate := range v.Messages {
		if candidate.Name == name {
			return candidate.Message
		}
	}
	t.Fatalf("vector %s missing", name)
	return ""
}

func (v pgpVectors) signedAt() time.Time {
	return time.Unix(v.SignedAt, 0)
}

func newDecryptorAt(t *testing.T, vectors pgpVectors, privateKeys string, now time.Time) *Decryptor {
	t.Helper()
	decryptor, err := NewDecryptor(DecryptorOptions{
		PrivateKeys:     privateKeys,
		SumsubPublicKey: vectors.Keys.Sumsub.PublicKey,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return decryptor
}

func newVectorDecryptor(t *testing.T, vectors pgpVectors) *Decryptor {
	t.Helper()
	return newDecryptorAt(t, vectors, vectors.Keys.Gateway.PrivateKey, vectors.signedAt().Add(time.Minute))
}

func TestDecryptsTheSignedVector(t *testing.T) {
	vectors := loadPGPVectors(t)
	plaintext, err := newVectorDecryptor(t, vectors).Decrypt([]byte(vectors.message(t, "signed-encrypted")))
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != vectors.Plaintext {
		t.Fatalf("plaintext mismatch: %s", plaintext)
	}
}

func TestRejectsMessagesNotSignedBySumsub(t *testing.T) {
	vectors := loadPGPVectors(t)
	decryptor := newVectorDecryptor(t, vectors)
	for _, vector := range vectors.Messages {
		if vector.Expect != "reject" {
			continue
		}
		_, err := decryptor.Decrypt([]byte(vector.Message))
		var decryptErr *DecryptError
		if !errors.As(err, &decryptErr) {
			t.Errorf("%s: expected DecryptError, got %v", vector.Name, err)
		}
	}
	if _, err := decryptor.Decrypt([]byte("not a pgp message")); err == nil {
		t.Error("garbage was accepted")
	}
}

func TestRejectsAStaleSignature(t *testing.T) {
	vectors := loadPGPVectors(t)
	decryptor := newDecryptorAt(t, vectors, vectors.Keys.Gateway.PrivateKey, vectors.signedAt().Add(10*time.Minute))
	_, err := decryptor.Decrypt([]byte(vectors.message(t, "signed-encrypted")))
	var decryptErr *DecryptError
	if !errors.As(err, &decryptErr) || !strings.Contains(decryptErr.Message, "time window") {
		t.Fatalf("expected a time window error, got %v", err)
	}
}

func TestRejectsAPlaintextOverTheLimit(t *testing.T) {
	vectors := loadPGPVectors(t)
	_, err := newVectorDecryptor(t, vectors).Decrypt([]byte(vectors.message(t, "oversized-plaintext")))
	var decryptErr *DecryptError
	if !errors.As(err, &decryptErr) || decryptErr.Message != "Request body is too large" {
		t.Fatalf("expected a size error, got %v", err)
	}
}

func TestDecryptsWithEveryConfiguredKeyDuringARotation(t *testing.T) {
	vectors := loadPGPVectors(t)
	keys := armoredPrivateKey(t) + "\n" + vectors.Keys.Gateway.PrivateKey
	decryptor := newDecryptorAt(t, vectors, keys, vectors.signedAt())
	plaintext, err := decryptor.Decrypt([]byte(vectors.message(t, "signed-encrypted")))
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != vectors.Plaintext {
		t.Fatalf("plaintext mismatch: %s", plaintext)
	}
}

func TestReproducesTheDigestOverTheArmoredBody(t *testing.T) {
	vectors := loadPGPVectors(t)
	digest, ok := ComputeDigest(vectors.Digest.Timestamp, []byte(vectors.message(t, vectors.Digest.Message)), vectors.Digest.SecretKey, vectors.Digest.Algorithm)
	if !ok || digest != vectors.Digest.Value {
		t.Fatalf("digest %s, expected %s", digest, vectors.Digest.Value)
	}
}

func TestAcceptsSingleLineKeys(t *testing.T) {
	vectors := loadPGPVectors(t)
	singleLine := strings.ReplaceAll(vectors.Keys.Gateway.PrivateKey, "\n", `\n`)
	if NormalizeArmored(singleLine) != vectors.Keys.Gateway.PrivateKey {
		t.Fatal("single-line key was not normalized")
	}
	if _, err := NewDecryptor(DecryptorOptions{PrivateKeys: singleLine, SumsubPublicKey: vectors.Keys.Sumsub.PublicKey}); err != nil {
		t.Fatal(err)
	}
}

func armoredPrivateKey(t *testing.T) string {
	t.Helper()
	entity, err := openpgp.NewEntity("rotation", "", "rotation@example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	writer, err := armor.Encode(&out, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(writer, nil); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}
