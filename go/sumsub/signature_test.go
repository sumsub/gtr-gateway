package sumsub

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type signatureVectors struct {
	SecretKey string            `json:"secretKey"`
	Timestamp string            `json:"timestamp"`
	Body      string            `json:"body"`
	Digests   map[string]string `json:"digests"`
}

func loadSignatureVectors(t *testing.T) signatureVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", "request-signature.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors signatureVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func (v signatureVectors) signedAt(t *testing.T) time.Time {
	t.Helper()
	seconds, err := strconv.ParseInt(v.Timestamp, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return time.Unix(seconds, 0)
}

func newVectorVerifier(t *testing.T, vectors signatureVectors, now time.Time, keys ...string) *Verifier {
	t.Helper()
	if len(keys) == 0 {
		keys = []string{vectors.SecretKey}
	}
	verifier, err := NewVerifier(VerifierOptions{SecretKeys: keys, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func signedHeader(timestamp, digest, algorithm string) http.Header {
	header := http.Header{}
	header.Set(TimestampHeader, timestamp)
	header.Set(DigestHeader, digest)
	header.Set(DigestAlgorithmHeader, algorithm)
	return header
}

func TestComputeDigestReproducesTheVectors(t *testing.T) {
	vectors := loadSignatureVectors(t)
	for algorithm, want := range vectors.Digests {
		got, ok := ComputeDigest(vectors.Timestamp, []byte(vectors.Body), vectors.SecretKey, algorithm)
		if !ok || got != want {
			t.Errorf("%s: got %q (ok=%v), want %q", algorithm, got, ok, want)
		}
	}
	if _, ok := ComputeDigest(vectors.Timestamp, []byte(vectors.Body), vectors.SecretKey, "HMAC_MD5_HEX"); ok {
		t.Error("unknown algorithm must not be accepted")
	}
}

func TestVerifierAcceptsValidRequests(t *testing.T) {
	vectors := loadSignatureVectors(t)
	verifier := newVectorVerifier(t, vectors, vectors.signedAt(t).Add(4*time.Minute))
	for algorithm, digest := range vectors.Digests {
		if err := verifier.Verify(signedHeader(vectors.Timestamp, digest, algorithm), []byte(vectors.Body)); err != nil {
			t.Errorf("%s: %v", algorithm, err)
		}
		if err := verifier.Verify(signedHeader(vectors.Timestamp, strings.ToUpper(digest), algorithm), []byte(vectors.Body)); err != nil {
			t.Errorf("%s upper-case: %v", algorithm, err)
		}
	}
}

func TestVerifierRejectsInvalidSignatures(t *testing.T) {
	vectors := loadSignatureVectors(t)
	verifier := newVectorVerifier(t, vectors, vectors.signedAt(t))
	digest := vectors.Digests["HMAC_SHA256_HEX"]
	body := []byte(vectors.Body)
	cases := map[string]error{
		"tampered body":       verifier.Verify(signedHeader(vectors.Timestamp, digest, "HMAC_SHA256_HEX"), append(append([]byte{}, body...), ' ')),
		"tampered timestamp":  verifier.Verify(signedHeader("1756368001", digest, "HMAC_SHA256_HEX"), body),
		"other algorithm":     verifier.Verify(signedHeader(vectors.Timestamp, vectors.Digests["HMAC_SHA512_HEX"], "HMAC_SHA256_HEX"), body),
		"missing digest":      verifier.Verify(signedHeader(vectors.Timestamp, "", "HMAC_SHA256_HEX"), body),
		"missing timestamp":   verifier.Verify(signedHeader("", digest, "HMAC_SHA256_HEX"), body),
		"missing algorithm":   verifier.Verify(signedHeader(vectors.Timestamp, digest, ""), body),
		"unknown algorithm":   verifier.Verify(signedHeader(vectors.Timestamp, digest, "HMAC_MD5_HEX"), body),
		"wrong secret key":    newVectorVerifier(t, vectors, vectors.signedAt(t), "another-secret-key-0123").Verify(signedHeader(vectors.Timestamp, digest, "HMAC_SHA256_HEX"), body),
		"non-numeric seconds": verifier.Verify(signedHeader("now", mustDigest(t, "now", body, vectors.SecretKey), "HMAC_SHA256_HEX"), body),
	}
	for name, err := range cases {
		var signatureErr *SignatureError
		if !errors.As(err, &signatureErr) || signatureErr.Message != "Request signature is missing or invalid" {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestVerifierRejectsStaleAndFutureTimestamps(t *testing.T) {
	vectors := loadSignatureVectors(t)
	header := signedHeader(vectors.Timestamp, vectors.Digests["HMAC_SHA256_HEX"], "HMAC_SHA256_HEX")
	for name, now := range map[string]time.Time{
		"stale":  vectors.signedAt(t).Add(6 * time.Minute),
		"future": vectors.signedAt(t).Add(-6 * time.Minute),
	} {
		err := newVectorVerifier(t, vectors, now).Verify(header, []byte(vectors.Body))
		var signatureErr *SignatureError
		if !errors.As(err, &signatureErr) || !strings.Contains(signatureErr.Message, "outside the allowed window") {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestVerifierAcceptsThePreviousKeyDuringARotation(t *testing.T) {
	vectors := loadSignatureVectors(t)
	verifier := newVectorVerifier(t, vectors, vectors.signedAt(t), "the-new-secret-key-0123", vectors.SecretKey)
	if err := verifier.Verify(signedHeader(vectors.Timestamp, vectors.Digests["HMAC_SHA256_HEX"], "HMAC_SHA256_HEX"), []byte(vectors.Body)); err != nil {
		t.Fatal(err)
	}
}

func TestNewVerifierRejectsUnusableKeys(t *testing.T) {
	for name, keys := range map[string][]string{
		"no keys":     nil,
		"empty key":   {""},
		"short key":   {"short"},
		"short extra": {"a-long-enough-secret-key", "short"},
	} {
		if _, err := NewVerifier(VerifierOptions{SecretKeys: keys}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewVerifier(VerifierOptions{SecretKeys: []string{"a-long-enough-secret-key", ""}}); err != nil {
		t.Errorf("an empty previous key must be skipped: %v", err)
	}
}

func mustDigest(t *testing.T, timestamp string, body []byte, key string) string {
	t.Helper()
	digest, ok := ComputeDigest(timestamp, body, key, "HMAC_SHA256_HEX")
	if !ok {
		t.Fatal("digest")
	}
	return digest
}
