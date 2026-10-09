package gateway

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sumsub/gtr-gateway/go/gtr"
	"github.com/sumsub/gtr-gateway/go/sumsub"
)

type pgpVectors struct {
	SignedAt int64 `json:"signedAt"`
	Keys     struct {
		Sumsub  struct{ PublicKey string }  `json:"sumsub"`
		Gateway struct{ PrivateKey string } `json:"gateway"`
	} `json:"keys"`
	Messages []struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	} `json:"messages"`
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

func (v pgpVectors) now() time.Time {
	return time.Unix(v.SignedAt, 0).Add(time.Minute)
}

func newEncryptedHandler(t *testing.T, vectors pgpVectors, decryptor *sumsub.Decryptor) (*fakeGTR, http.Handler) {
	t.Helper()
	fake := &fakeGTR{response: gtr.Response{Status: 200, Body: map[string]any{"success": true}}}
	handler := mustHandler(t, Options{
		GTR:              fake,
		KeyPair:          newKeyPair(t),
		SumsubSecretKeys: []string{secret},
		Decryptor:        decryptor,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:              vectors.now,
	})
	return fake, handler
}

func encryptedRequest(t *testing.T, vectors pgpVectors, path, body, digest string) *http.Request {
	t.Helper()
	timestamp := strconv.FormatInt(vectors.now().Unix(), 10)
	if digest == "" {
		var ok bool
		if digest, ok = sumsub.ComputeDigest(timestamp, []byte(body), secret, "HMAC_SHA256_HEX"); !ok {
			t.Fatal("digest")
		}
	}
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/pgp-encrypted")
	request.Header.Set(sumsub.EncryptionHeader, sumsub.EncryptionHeaderValue)
	request.Header.Set(sumsub.TimestampHeader, timestamp)
	request.Header.Set(sumsub.DigestHeader, digest)
	request.Header.Set(sumsub.DigestAlgorithmHeader, "HMAC_SHA256_HEX")
	return request
}

func vectorDecryptor(t *testing.T, vectors pgpVectors) *sumsub.Decryptor {
	t.Helper()
	decryptor, err := sumsub.NewDecryptor(sumsub.DecryptorOptions{
		PrivateKeys:     vectors.Keys.Gateway.PrivateKey,
		SumsubPublicKey: vectors.Keys.Sumsub.PublicKey,
		Now:             vectors.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return decryptor
}

func TestDecryptsAnEncryptedOneStepRequest(t *testing.T) {
	vectors := loadPGPVectors(t)
	_, handler := newEncryptedHandler(t, vectors, vectorDecryptor(t, vectors))
	recorder := serve(handler, encryptedRequest(t, vectors, "/tr/gtr/verify/one-step", vectors.message(t, "signed-encrypted"), ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	if body := decodeJSON(t, recorder); body["success"] != true {
		t.Fatalf("unexpected response %v", body)
	}
}

func TestVerifiesTheDigestOverTheCiphertext(t *testing.T) {
	vectors := loadPGPVectors(t)
	_, handler := newEncryptedHandler(t, vectors, vectorDecryptor(t, vectors))
	recorder := serve(handler, encryptedRequest(t, vectors, "/tr/gtr/verify/one-step", vectors.message(t, "signed-encrypted"), "not-the-digest"))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", recorder.Code)
	}
}

func TestRejectsVectorsNotSignedBySumsub(t *testing.T) {
	vectors := loadPGPVectors(t)
	_, handler := newEncryptedHandler(t, vectors, vectorDecryptor(t, vectors))
	for _, name := range []string{"unsigned", "unknown-signer", "spoofed-key-id", "oversized-plaintext"} {
		recorder := serve(handler, encryptedRequest(t, vectors, "/tr/gtr/verify/one-step", vectors.message(t, name), ""))
		if recorder.Code != http.StatusUnprocessableEntity || decodeJSON(t, recorder)["error"] != "crypto_failed" {
			t.Errorf("%s: status %d body %s", name, recorder.Code, recorder.Body.String())
		}
	}
}

func TestRejectsEncryptedRequestsWithoutAPrivateKey(t *testing.T) {
	vectors := loadPGPVectors(t)
	_, handler := newEncryptedHandler(t, vectors, nil)
	recorder := serve(handler, encryptedRequest(t, vectors, "/tr/gtr/verify/one-step", vectors.message(t, "signed-encrypted"), ""))
	if recorder.Code != http.StatusUnprocessableEntity || decodeJSON(t, recorder)["error"] != "crypto_failed" {
		t.Fatalf("status %d body %s", recorder.Code, recorder.Body.String())
	}
}
