package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sumsub/gtr-gateway/go/gtr"
	"github.com/sumsub/gtr-gateway/go/sumsub"
)

type fakeSumsub struct {
	calls    []map[string]any
	response sumsub.Response
	err      error
}

func (f *fakeSumsub) ForwardCallback(_ context.Context, body any) (sumsub.Response, error) {
	raw, _ := json.Marshal(body)
	var copied map[string]any
	_ = json.Unmarshal(raw, &copied)
	f.calls = append(f.calls, copied)
	if f.err != nil {
		return sumsub.Response{}, f.err
	}
	return f.response, nil
}

func newCallbackHandler(t *testing.T, withSumsub bool) (*fakeSumsub, gtr.KeyPair, http.Handler) {
	t.Helper()
	fake := &fakeSumsub{response: sumsub.Response{Status: 200, Body: map[string]any{"verifyStatus": float64(100000)}}}
	keyPair := newKeyPair(t)
	options := Options{
		GTR:              &fakeGTR{},
		KeyPair:          keyPair,
		SumsubSecretKeys: []string{secret},
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if withSumsub {
		options.Sumsub = fake
	}
	return fake, keyPair, mustHandler(t, options)
}

func postCallback(handler http.Handler, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost, "/tr/gtr/callback", strings.NewReader(string(raw)))
	request.Header.Set("Content-Type", "application/json")
	return serve(handler, request)
}

func piiCallback(t *testing.T, ivms any, gateway, originator, encryptWith gtr.KeyPair) map[string]any {
	t.Helper()
	plaintext, _ := json.Marshal(ivms)
	encrypted, err := gtr.EncryptPayload(plaintext, encryptWith, gateway.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"requestId":       "cb-1",
		"invokeVaspCode":  "cp",
		"originatorVasp":  "cp",
		"beneficiaryVasp": "me",
		"callbackType":    4,
		"callbackData": map[string]any{
			"requestId":             "r1",
			"initiatorVasp":         "cp",
			"receiverVasp":          "me",
			"initiatorPublicKey":    gtr.PublicKeyBase64(originator),
			"receiverPublicKey":     gtr.PublicKeyBase64(gateway),
			"encryptedPayload":      encrypted,
			"ticker":                "USDT",
			"verificationDirection": 2,
		},
	}
}

func TestCallbackDecryptsAndReEncrypts(t *testing.T) {
	fake, gateway, handler := newCallbackHandler(t, true)
	originator := newKeyPair(t)
	originatorIvms := map[string]any{"ivms101": map[string]any{"originator": map[string]any{"name": "Alice"}}}
	beneficiaryIvms := map[string]any{"ivms101": map[string]any{"beneficiary": map[string]any{"name": "Bob"}}}
	fake.response = sumsub.Response{Status: 200, Body: map[string]any{
		"verifyStatus": float64(100000),
		"data":         map[string]any{"payload": beneficiaryIvms, "secretType": float64(1), "verifyFields": []any{map[string]any{"type": "7"}}},
	}}

	recorder := postCallback(handler, piiCallback(t, originatorIvms, gateway, originator, originator))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}

	forwardedData, _ := fake.calls[0]["callbackData"].(map[string]any)
	if fake.calls[0]["callbackType"] != float64(4) {
		t.Errorf("callbackType %v", fake.calls[0]["callbackType"])
	}
	if _, hasEncrypted := forwardedData["encryptedPayload"]; hasEncrypted {
		t.Error("encryptedPayload must not be forwarded")
	}
	payloadJSON, _ := json.Marshal(forwardedData["payload"])
	wantJSON, _ := json.Marshal(originatorIvms)
	if string(payloadJSON) != string(wantJSON) {
		t.Errorf("forwarded payload %s", payloadJSON)
	}
	if forwardedData["ticker"] != "USDT" || forwardedData["initiatorPublicKey"] != gtr.PublicKeyBase64(originator) {
		t.Errorf("forwarded data %v", forwardedData)
	}

	answer := decodeJSON(t, recorder)
	data, _ := answer["data"].(map[string]any)
	if answer["verifyStatus"] != float64(100000) || data["secretType"] != float64(1) {
		t.Errorf("answer %v", answer)
	}
	if _, hasPayload := data["payload"]; hasPayload {
		t.Error("plaintext payload must not reach GTR")
	}
	if data["initiatorPublicKey"] != gtr.PublicKeyBase64(gateway) {
		t.Error("initiatorPublicKey must be the gateway public key")
	}
	decrypted, err := gtr.DecryptPayload(data["encryptedPayload"].(string), originator, gateway.PublicKey)
	if err != nil {
		t.Fatalf("originator cannot decrypt: %v", err)
	}
	wantAnswer, _ := json.Marshal(beneficiaryIvms)
	if string(decrypted) != string(wantAnswer) {
		t.Errorf("decrypted answer %s", decrypted)
	}
}

func TestCallbackForwardsOtherTypesUnchanged(t *testing.T) {
	fake, _, handler := newCallbackHandler(t, true)
	fake.response = sumsub.Response{Status: 200, Body: map[string]any{"verifyStatus": float64(100000), "verifyMessage": "TX ID Received"}}
	body := map[string]any{"requestId": "cb-2", "callbackType": 7, "callbackData": map[string]any{"requestId": "r1", "txId": "0xabc"}}

	recorder := postCallback(handler, body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d", recorder.Code)
	}
	if answer := decodeJSON(t, recorder); answer["verifyMessage"] != "TX ID Received" {
		t.Errorf("answer %v", answer)
	}
	forwardedData, _ := fake.calls[0]["callbackData"].(map[string]any)
	if fake.calls[0]["callbackType"] != float64(7) || forwardedData["txId"] != "0xabc" {
		t.Errorf("forwarded %v", fake.calls[0])
	}
}

func TestCallbackAnswers200002WhenPayloadCannotBeDecrypted(t *testing.T) {
	fake, gateway, handler := newCallbackHandler(t, true)
	originator := newKeyPair(t)
	recorder := postCallback(handler, piiCallback(t, map[string]any{"ivms101": map[string]any{}}, gateway, originator, newKeyPair(t)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d", recorder.Code)
	}
	if answer := decodeJSON(t, recorder); answer["verifyStatus"] != float64(200002) {
		t.Errorf("answer %v", answer)
	}
	if len(fake.calls) != 0 {
		t.Error("Sumsub must not be called")
	}
}

func TestCallbackMapsSumsubFailuresTo502(t *testing.T) {
	fake, _, handler := newCallbackHandler(t, true)
	fake.err = &sumsub.UnreachableError{Err: errors.New("connection refused")}
	recorder := postCallback(handler, map[string]any{"requestId": "cb-3", "callbackType": 0})
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status %d", recorder.Code)
	}
	if answer := decodeJSON(t, recorder); answer["verifyStatus"] != float64(100001) || answer["verifyMessage"] != "Sumsub API is unreachable" {
		t.Errorf("answer %v", answer)
	}

	fake.err = nil
	fake.response = sumsub.Response{Status: 401, Body: map[string]any{"code": float64(401)}}
	recorder = postCallback(handler, map[string]any{"requestId": "cb-4", "callbackType": 0})
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status %d", recorder.Code)
	}
	if answer := decodeJSON(t, recorder); answer["verifyStatus"] != float64(100001) {
		t.Errorf("answer %v", answer)
	}
}

func TestCallbackRejectsContainerWithoutType(t *testing.T) {
	_, _, handler := newCallbackHandler(t, true)
	if recorder := postCallback(handler, map[string]any{"requestId": "cb-5"}); recorder.Code != http.StatusBadRequest {
		t.Fatalf("status %d", recorder.Code)
	}
}

func TestCallbackRouteAbsentWithoutSumsub(t *testing.T) {
	_, _, handler := newCallbackHandler(t, false)
	if recorder := postCallback(handler, map[string]any{"callbackType": 0}); recorder.Code != http.StatusNotFound {
		t.Fatalf("status %d", recorder.Code)
	}
}
