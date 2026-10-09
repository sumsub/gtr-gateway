package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sumsub/gtr-gateway/go/gtr"
	"github.com/sumsub/gtr-gateway/go/sumsub"
)

const secret = "sumsub-test-secret-key"

type recordedCall struct {
	method string
	body   any
}

type fakeGTR struct {
	calls    []recordedCall
	response gtr.Response
	err      error
}

func (f *fakeGTR) VASPDetail(_ context.Context, vaspCode string) (gtr.Response, error) {
	return f.record("VASPDetail", vaspCode)
}

func (f *fakeGTR) AutoAddressVASPDetection(_ context.Context, body any) (gtr.Response, error) {
	return f.record("AutoAddressVASPDetection", body)
}

func (f *fakeGTR) OneStep(_ context.Context, body map[string]any) (gtr.Response, error) {
	return f.record("OneStep", body)
}

func (f *fakeGTR) SubmitTxID(_ context.Context, body any) (gtr.Response, error) {
	return f.record("SubmitTxID", body)
}

func (f *fakeGTR) EndTravelRule(_ context.Context, body any) (gtr.Response, error) {
	return f.record("EndTravelRule", body)
}

func (f *fakeGTR) record(method string, body any) (gtr.Response, error) {
	f.calls = append(f.calls, recordedCall{method: method, body: body})
	if f.err != nil {
		return gtr.Response{}, f.err
	}
	return f.response, nil
}

func newKeyPair(t *testing.T) gtr.KeyPair {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return gtr.KeyPair{PublicKey: public, PrivateKey: private}
}

func newHandler(t *testing.T) (*fakeGTR, gtr.KeyPair, http.Handler) {
	t.Helper()
	fake := &fakeGTR{response: gtr.Response{Status: 200, Body: map[string]any{"success": true}}}
	keyPair := newKeyPair(t)
	handler := mustHandler(t, Options{
		GTR:              fake,
		KeyPair:          keyPair,
		SumsubSecretKeys: []string{secret},
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return fake, keyPair, handler
}

func mustHandler(t *testing.T, options Options) http.Handler {
	t.Helper()
	handler, err := NewHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func signedRequest(t *testing.T, path, body, algorithm, key string) *http.Request {
	t.Helper()
	return signedRequestAt(t, path, body, algorithm, key, time.Now())
}

func signedRequestAt(t *testing.T, path, body, algorithm, key string, at time.Time) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json;charset=UTF-8")
	timestamp := strconv.FormatInt(at.Unix(), 10)
	digest, ok := sumsub.ComputeDigest(timestamp, []byte(body), key, algorithm)
	if !ok {
		t.Fatalf("unknown algorithm %s", algorithm)
	}
	request.Header.Set(sumsub.TimestampHeader, timestamp)
	request.Header.Set(sumsub.DigestHeader, digest)
	request.Header.Set(sumsub.DigestAlgorithmHeader, algorithm)
	return request
}

func serve(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeJSON(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, recorder.Body.String())
	}
	return body
}

func TestHealthNeedsNoSignature(t *testing.T) {
	_, _, handler := newHandler(t)
	recorder := serve(handler, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d", recorder.Code)
	}
}

func TestRejectsUnsignedRequests(t *testing.T) {
	fake, _, handler := newHandler(t)
	request := httptest.NewRequest(http.MethodPost, "/tr/gtr/vasp/detail", strings.NewReader(`{"vaspCode":"abc"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := serve(handler, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", recorder.Code)
	}
	if body := decodeJSON(t, recorder); body["error"] != "invalid_signature" {
		t.Errorf("body %v", body)
	}
	if len(fake.calls) != 0 {
		t.Error("GTR must not be called")
	}
}

func TestRejectsWrongSecret(t *testing.T) {
	_, _, handler := newHandler(t)
	recorder := serve(handler, signedRequest(t, "/tr/gtr/vasp/detail", `{"vaspCode":"abc"}`, "HMAC_SHA256_HEX", "wrong"))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", recorder.Code)
	}
}

func TestRejectsAStaleTimestamp(t *testing.T) {
	fake, _, handler := newHandler(t)
	recorder := serve(handler, signedRequestAt(t, "/tr/gtr/vasp/detail", `{"vaspCode":"abc"}`, "HMAC_SHA256_HEX", secret, time.Now().Add(-10*time.Minute)))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", recorder.Code)
	}
	if body := decodeJSON(t, recorder); body["error"] != "invalid_signature" || !strings.Contains(body["message"].(string), "outside the allowed window") {
		t.Errorf("body %v", body)
	}
	if len(fake.calls) != 0 {
		t.Error("GTR must not be called")
	}
}

func TestAcceptsThePreviousSecretKeyDuringARotation(t *testing.T) {
	fake := &fakeGTR{response: gtr.Response{Status: 200, Body: map[string]any{"success": true}}}
	handler := mustHandler(t, Options{GTR: fake, KeyPair: newKeyPair(t), SumsubSecretKeys: []string{"the-new-secret-key-0123", secret}})
	recorder := serve(handler, signedRequest(t, "/tr/gtr/vasp/detail", `{"vaspCode":"abc"}`, "HMAC_SHA256_HEX", secret))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestNewHandlerValidatesItsOptions(t *testing.T) {
	keyPair := newKeyPair(t)
	for name, options := range map[string]Options{
		"no GTR client":    {KeyPair: keyPair, SumsubSecretKeys: []string{secret}},
		"no key pair":      {GTR: &fakeGTR{}, SumsubSecretKeys: []string{secret}},
		"no secret key":    {GTR: &fakeGTR{}, KeyPair: keyPair},
		"empty secret key": {GTR: &fakeGTR{}, KeyPair: keyPair, SumsubSecretKeys: []string{""}},
		"short secret key": {GTR: &fakeGTR{}, KeyPair: keyPair, SumsubSecretKeys: []string{"short"}},
	} {
		if _, err := NewHandler(options); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRejectsAnOversizedBody(t *testing.T) {
	fake, _, handler := newHandler(t)
	body := `{"vaspCode":"` + strings.Repeat("a", maxRequestBytes) + `"}`
	recorder := serve(handler, signedRequest(t, "/tr/gtr/vasp/detail", body, "HMAC_SHA256_HEX", secret))
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", recorder.Code)
	}
	if len(fake.calls) != 0 {
		t.Error("GTR must not be called")
	}
}

func TestForwardsVASPDetail(t *testing.T) {
	for _, algorithm := range []string{"HMAC_SHA1_HEX", "HMAC_SHA256_HEX", "HMAC_SHA512_HEX"} {
		t.Run(algorithm, func(t *testing.T) {
			fake, _, handler := newHandler(t)
			fake.response = gtr.Response{Status: 200, Body: map[string]any{"success": true, "data": map[string]any{"vaspCode": "abc"}}}
			recorder := serve(handler, signedRequest(t, "/tr/gtr/vasp/detail", `{"vaspCode":"abc"}`, algorithm, secret))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
			}
			if body := decodeJSON(t, recorder); body["success"] != true {
				t.Errorf("body %v", body)
			}
			if len(fake.calls) != 1 || fake.calls[0].method != "VASPDetail" || fake.calls[0].body != "abc" {
				t.Errorf("calls %v", fake.calls)
			}
		})
	}
}

func TestPassesGTRErrorStatusThrough(t *testing.T) {
	fake, _, handler := newHandler(t)
	fake.response = gtr.Response{Status: 400, Body: map[string]any{"success": false, "verifyStatus": float64(100004)}}
	recorder := serve(handler, signedRequest(t, "/tr/gtr/verify/tx/submit", `{"requestId":"r1","txId":"0xabc"}`, "HMAC_SHA256_HEX", secret))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status %d", recorder.Code)
	}
	if body := decodeJSON(t, recorder); body["verifyStatus"] != float64(100004) {
		t.Errorf("body %v", body)
	}
	forwarded, _ := fake.calls[0].body.(map[string]any)
	if fake.calls[0].method != "SubmitTxID" || forwarded["txId"] != "0xabc" {
		t.Errorf("calls %v", fake.calls)
	}
}

func TestEncryptsOneStepPayload(t *testing.T) {
	fake, gatewayKeys, handler := newHandler(t)
	counterparty := newKeyPair(t)
	payload := map[string]any{"ivms101": map[string]any{"originator": map[string]any{"name": "Alice"}}}
	request := map[string]any{
		"requestId":           "r1",
		"targetVaspCode":      "cp",
		"targetVaspPublicKey": gtr.PublicKeyBase64(counterparty),
		"sourceVaspCode":      "me",
		"ticker":              "USDT",
		"payload":             payload,
	}
	body, _ := json.Marshal(request)
	recorder := serve(handler, signedRequest(t, "/tr/gtr/verify/one-step", string(body), "HMAC_SHA256_HEX", secret))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}

	forwarded, _ := fake.calls[0].body.(map[string]any)
	if fake.calls[0].method != "OneStep" {
		t.Fatalf("calls %v", fake.calls)
	}
	if _, hasPayload := forwarded["payload"]; hasPayload {
		t.Error("plaintext payload must not be forwarded")
	}
	for key, want := range map[string]string{"requestId": "r1", "targetVaspCode": "cp", "sourceVaspCode": "me", "ticker": "USDT"} {
		if forwarded[key] != want {
			t.Errorf("%s: got %v, want %s", key, forwarded[key], want)
		}
	}
	if forwarded["initiatorPublicKey"] != gtr.PublicKeyBase64(gatewayKeys) {
		t.Error("initiatorPublicKey must be the gateway public key")
	}
	encrypted, _ := forwarded["encryptedPayload"].(string)
	decrypted, err := gtr.DecryptPayload(encrypted, counterparty, gatewayKeys.PublicKey)
	if err != nil {
		t.Fatalf("counterparty cannot decrypt: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(decrypted, &got); err != nil || got["ivms101"] == nil {
		t.Errorf("decrypted payload %s", decrypted)
	}
}

func TestRejectsOneStepWithoutPayload(t *testing.T) {
	fake, _, handler := newHandler(t)
	recorder := serve(handler, signedRequest(t, "/tr/gtr/verify/one-step", `{"requestId":"r1","targetVaspPublicKey":"x"}`, "HMAC_SHA256_HEX", secret))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status %d", recorder.Code)
	}
	if body := decodeJSON(t, recorder); body["error"] != "invalid_request" {
		t.Errorf("body %v", body)
	}
	if len(fake.calls) != 0 {
		t.Error("GTR must not be called")
	}
}

func TestReportsInvalidCounterpartyKey(t *testing.T) {
	_, _, handler := newHandler(t)
	recorder := serve(handler, signedRequest(t, "/tr/gtr/verify/one-step", `{"requestId":"r1","targetVaspPublicKey":"AAAA","payload":{}}`, "HMAC_SHA256_HEX", secret))
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	if body := decodeJSON(t, recorder); body["error"] != "crypto_failed" {
		t.Errorf("body %v", body)
	}
}

func TestMapsGTRConnectivityProblemsTo502(t *testing.T) {
	fake, _, handler := newHandler(t)
	fake.err = &gtr.UnreachableError{Err: errors.New("connection refused")}
	recorder := serve(handler, signedRequest(t, "/tr/gtr/verify/end", `{"requestId":"r1","reasonType":"CANCELLED"}`, "HMAC_SHA256_HEX", secret))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status %d", recorder.Code)
	}
	if body := decodeJSON(t, recorder); body["error"] != "gtr_unreachable" {
		t.Errorf("body %v", body)
	}
}

func TestRejectsMalformedJSON(t *testing.T) {
	_, _, handler := newHandler(t)
	recorder := serve(handler, signedRequest(t, "/tr/gtr/vasp/detail", `{"vaspCode":`, "HMAC_SHA256_HEX", secret))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status %d", recorder.Code)
	}
	if body := decodeJSON(t, recorder); body["error"] != "invalid_request" {
		t.Errorf("body %v", body)
	}
}
