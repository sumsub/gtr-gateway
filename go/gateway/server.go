// Package gateway exposes the five endpoints Sumsub calls and forwards them to GTR.
package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/sumsub/gtr-gateway/go/gtr"
	"github.com/sumsub/gtr-gateway/go/sumsub"
)

// DefaultRoutePrefix is the path prefix of the gateway routes; configure the same prefix in the Sumsub dashboard.
const DefaultRoutePrefix = "/tr/gtr"

const maxRequestBytes = 1 << 20

// Options wires the handler to its dependencies.
type Options struct {
	GTR     gtr.API
	KeyPair gtr.KeyPair
	// SumsubSecretKeys are the dashboard secret keys: the current one, plus the previous one during a rotation.
	SumsubSecretKeys []string
	// TimestampTolerance is the accepted clock difference to Sumsub; zero means sumsub.DefaultTimestampTolerance.
	TimestampTolerance time.Duration
	// Sumsub forwards GTR callbacks; when nil the inbound route is not exposed.
	Sumsub sumsub.CallbackAPI
	// Decryptor decrypts requests when payload encryption is enabled in the dashboard (contract §2.1).
	Decryptor   *sumsub.Decryptor
	RoutePrefix string
	// Logger receives errors and one line per request; nil sends errors to slog.Default and skips the request log.
	Logger *slog.Logger
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
}

type server struct {
	gtr       gtr.API
	sumsub    sumsub.CallbackAPI
	keyPair   gtr.KeyPair
	verifier  *sumsub.Verifier
	decryptor *sumsub.Decryptor
	logger    *slog.Logger
}

// handlerFunc receives the verified raw body and returns the GTR response to forward.
type handlerFunc func(ctx context.Context, rawBody []byte) (gtr.Response, error)

type requestError struct{ message string }

func (e *requestError) Error() string { return e.message }

// NewHandler builds the HTTP handler: /health plus the signed gateway routes under the prefix.
// It refuses to start without a GTR client, a valid key pair or a usable Sumsub secret key.
func NewHandler(options Options) (http.Handler, error) {
	if options.GTR == nil {
		return nil, errors.New("gateway: the GTR client is required")
	}
	if len(options.KeyPair.PublicKey) != ed25519.PublicKeySize || len(options.KeyPair.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("gateway: the Ed25519 key pair is required")
	}
	verifier, err := sumsub.NewVerifier(sumsub.VerifierOptions{
		SecretKeys: options.SumsubSecretKeys,
		Tolerance:  options.TimestampTolerance,
		Now:        options.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}
	prefix := options.RoutePrefix
	if prefix == "" {
		prefix = DefaultRoutePrefix
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := &server{gtr: options.GTR, sumsub: options.Sumsub, keyPair: options.KeyPair, verifier: verifier, decryptor: options.Decryptor, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("POST "+prefix+"/vasp/detail", s.signed(s.vaspDetail))
	mux.Handle("POST "+prefix+"/verify/auto-address-vasp-detection", s.signed(s.passthrough(s.gtr.AutoAddressVASPDetection)))
	mux.Handle("POST "+prefix+"/verify/one-step", s.signed(s.oneStep))
	mux.Handle("POST "+prefix+"/verify/tx/submit", s.signed(s.passthrough(s.gtr.SubmitTxID)))
	mux.Handle("POST "+prefix+"/verify/end", s.signed(s.passthrough(s.gtr.EndTravelRule)))
	if s.sumsub != nil {
		mux.HandleFunc("POST "+prefix+"/callback", s.callback)
	} else {
		logger.Warn("Sumsub callback client is not configured: GTR callbacks (inbound Travel Rule) are disabled")
	}
	if options.Logger == nil {
		return mux, nil
	}
	return withRequestLog(options.Logger, mux), nil
}

// signed reads the raw body, verifies the Sumsub signature and timestamp over it, decrypts it when it is
// a PGP message and runs the handler.
func (s *server) signed(handle handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawBody, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "request body cannot be read")
			return
		}
		if len(rawBody) > maxRequestBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body is too large")
			return
		}
		if err := s.verifier.Verify(r.Header, rawBody); err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_signature", err.Error())
			return
		}
		if r.Header.Get(sumsub.EncryptionHeader) == sumsub.EncryptionHeaderValue {
			if s.decryptor == nil {
				writeError(w, http.StatusUnprocessableEntity, "crypto_failed", "Request is encrypted but the gateway has no PGP private key configured")
				return
			}
			plaintext, err := s.decryptor.Decrypt(rawBody)
			if err != nil {
				writeError(w, http.StatusUnprocessableEntity, "crypto_failed", err.Error())
				return
			}
			rawBody = plaintext
		}

		response, err := handle(r.Context(), rawBody)
		if err != nil {
			s.writeMappedError(w, err)
			return
		}
		forward(w, response)
	})
}

func (s *server) vaspDetail(ctx context.Context, rawBody []byte) (gtr.Response, error) {
	var body struct {
		VASPCode string `json:"vaspCode"`
	}
	if err := decodeObject(rawBody, &body); err != nil {
		return gtr.Response{}, err
	}
	if body.VASPCode == "" {
		return gtr.Response{}, &requestError{message: "vaspCode is required"}
	}
	return s.gtr.VASPDetail(ctx, body.VASPCode)
}

func (s *server) passthrough(call func(context.Context, any) (gtr.Response, error)) handlerFunc {
	return func(ctx context.Context, rawBody []byte) (gtr.Response, error) {
		var body map[string]any
		if err := decodeObject(rawBody, &body); err != nil {
			return gtr.Response{}, err
		}
		return call(ctx, body)
	}
}

// oneStep replaces the plaintext payload with the encrypted GTR envelope before forwarding.
func (s *server) oneStep(ctx context.Context, rawBody []byte) (gtr.Response, error) {
	var body map[string]any
	if err := decodeObject(rawBody, &body); err != nil {
		return gtr.Response{}, err
	}
	payload, ok := body["payload"].(map[string]any)
	if !ok {
		return gtr.Response{}, &requestError{message: "payload must be a JSON object"}
	}
	targetPublicKey, ok := body["targetVaspPublicKey"].(string)
	if !ok || targetPublicKey == "" {
		return gtr.Response{}, &requestError{message: "targetVaspPublicKey is required"}
	}

	counterparty, err := gtr.ParseEd25519PublicKey(targetPublicKey)
	if err != nil {
		return gtr.Response{}, err
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return gtr.Response{}, &requestError{message: "payload cannot be serialized"}
	}
	encrypted, err := gtr.EncryptPayload(plaintext, s.keyPair, counterparty)
	if err != nil {
		return gtr.Response{}, err
	}

	delete(body, "payload")
	body["encryptedPayload"] = encrypted
	body["initiatorPublicKey"] = gtr.PublicKeyBase64(s.keyPair)
	return s.gtr.OneStep(ctx, body)
}

func (s *server) writeMappedError(w http.ResponseWriter, err error) {
	var badRequest *requestError
	var cryptoErr *gtr.CryptoError
	var unreachable *gtr.UnreachableError
	var loginErr *gtr.LoginError
	switch {
	case errors.As(err, &badRequest):
		writeError(w, http.StatusBadRequest, "invalid_request", badRequest.message)
	case errors.As(err, &cryptoErr):
		writeError(w, http.StatusUnprocessableEntity, "crypto_failed", cryptoErr.Message)
	case errors.As(err, &unreachable):
		s.logger.Error("GTR unreachable", "error", err)
		writeError(w, http.StatusBadGateway, "gtr_unreachable", "GTR API is unreachable")
	case errors.As(err, &loginErr):
		s.logger.Error("GTR login failed", "error", err)
		writeError(w, http.StatusBadGateway, "gtr_login_failed", loginErr.Error())
	default:
		s.logger.Error("unhandled error", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "Internal error")
	}
}

func decodeObject(rawBody []byte, target any) error {
	if err := json.Unmarshal(rawBody, target); err != nil {
		return &requestError{message: "request body must be a JSON object"}
	}
	return nil
}

// forward writes the GTR response to Sumsub unchanged.
func forward(w http.ResponseWriter, response gtr.Response) {
	if text, ok := response.Body.(string); ok {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(response.Status)
		_, _ = io.WriteString(w, text)
		return
	}
	writeJSON(w, response.Status, response.Body)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// withRequestLog logs method, path, status and duration. Bodies are never logged: they carry PII.
func withRequestLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		logger.Info("request completed",
			"method", r.Method, "path", r.URL.Path, "status", recorder.status, "duration", time.Since(start))
	})
}
