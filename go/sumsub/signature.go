// Package sumsub implements the Sumsub side of the gateway contract: request signature verification,
// PGP decryption, app-token signing and the client that forwards GTR callbacks to Sumsub.
package sumsub

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC_SHA1_HEX is still offered by the Sumsub dashboard.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	DigestHeader          = "X-Payload-Digest"
	DigestAlgorithmHeader = "X-Payload-Digest-Alg"
	TimestampHeader       = "X-Payload-Timestamp"
)

// DefaultTimestampTolerance is how far a request timestamp may be from the gateway clock.
const DefaultTimestampTolerance = 5 * time.Minute

// MinSecretKeyLength is the shortest accepted secret key; the Sumsub dashboard generates 27 characters.
const MinSecretKeyLength = 16

var hashByAlgorithm = map[string]func() hash.Hash{
	"HMAC_SHA1_HEX":   sha1.New,
	"HMAC_SHA256_HEX": sha256.New,
	"HMAC_SHA512_HEX": sha512.New,
}

// ComputeDigest returns the hex HMAC of timestamp + "." + rawBody; ok is false for an unknown algorithm.
func ComputeDigest(timestamp string, rawBody []byte, secretKey, algorithm string) (digest string, ok bool) {
	newHash, known := hashByAlgorithm[algorithm]
	if !known {
		return "", false
	}
	mac := hmac.New(newHash, []byte(secretKey))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(rawBody)
	return hex.EncodeToString(mac.Sum(nil)), true
}

// SignatureError explains why a request was rejected; the gateway answers 401.
type SignatureError struct{ Message string }

func (e *SignatureError) Error() string { return e.Message }

var errInvalidSignature = &SignatureError{Message: "Request signature is missing or invalid"}

// VerifierOptions configures a Verifier.
type VerifierOptions struct {
	// SecretKeys are the dashboard secret keys: the current one, plus the previous one during a rotation.
	SecretKeys []string
	// Tolerance is the accepted distance between the request timestamp and Now; zero means DefaultTimestampTolerance.
	Tolerance time.Duration
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
}

// Verifier checks the signature and the timestamp Sumsub puts on every gateway request.
type Verifier struct {
	secretKeys []string
	tolerance  time.Duration
	now        func() time.Time
}

// NewVerifier skips empty keys and refuses to start without a key or with a key shorter than MinSecretKeyLength.
func NewVerifier(options VerifierOptions) (*Verifier, error) {
	var keys []string
	for _, key := range options.SecretKeys {
		if key == "" {
			continue
		}
		if len(key) < MinSecretKeyLength {
			return nil, fmt.Errorf("the Sumsub secret key must be at least %d characters long", MinSecretKeyLength)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("the Sumsub secret key is required")
	}
	verifier := &Verifier{secretKeys: keys, tolerance: options.Tolerance, now: options.Now}
	if verifier.tolerance <= 0 {
		verifier.tolerance = DefaultTimestampTolerance
	}
	if verifier.now == nil {
		verifier.now = time.Now
	}
	return verifier, nil
}

// Verify checks X-Payload-Digest over the timestamp and the raw body in constant time, then the timestamp age.
func (v *Verifier) Verify(header http.Header, rawBody []byte) error {
	timestamp := header.Get(TimestampHeader)
	digest := strings.ToLower(header.Get(DigestHeader))
	algorithm := header.Get(DigestAlgorithmHeader)
	if timestamp == "" || digest == "" {
		return errInvalidSignature
	}
	matched := false
	for _, key := range v.secretKeys {
		expected, ok := ComputeDigest(timestamp, rawBody, key, algorithm)
		if !ok {
			return errInvalidSignature
		}
		if hmac.Equal([]byte(expected), []byte(digest)) {
			matched = true
		}
	}
	if !matched {
		return errInvalidSignature
	}
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errInvalidSignature
	}
	if v.now().Sub(time.Unix(seconds, 0)).Abs() > v.tolerance {
		return &SignatureError{Message: "Request timestamp is outside the allowed window; check the gateway clock"}
	}
	return nil
}
