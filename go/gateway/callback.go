package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/sumsub/gtr-gateway/go/gtr"
	"github.com/sumsub/gtr-gateway/go/sumsub"
)

const (
	piiVerificationCallback = 4
	gtrCommonFail           = 100001
	gtrCantDecrypt          = 200002
)

// callback receives GTR callbacks, forwards them to Sumsub and returns the answer to GTR.
// PII is encrypted between GTR and the gateway and travels in plaintext to Sumsub.
func (s *server) callback(w http.ResponseWriter, r *http.Request) {
	rawBody, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes))
	if err != nil {
		writeGTRError(w, http.StatusBadRequest, gtrCommonFail, "request body cannot be read")
		return
	}
	var container map[string]any
	if err := json.Unmarshal(rawBody, &container); err != nil || container == nil {
		writeGTRError(w, http.StatusBadRequest, gtrCommonFail, "request body must be a JSON object")
		return
	}
	callbackType, ok := container["callbackType"].(float64)
	if !ok {
		writeGTRError(w, http.StatusBadRequest, gtrCommonFail, "callbackType is required")
		return
	}

	data, _ := container["callbackData"].(map[string]any)
	isPIICallback := int(callbackType) == piiVerificationCallback && data != nil
	initiatorPublicKey, _ := data["initiatorPublicKey"].(string)

	if encrypted, ok := data["encryptedPayload"].(string); isPIICallback && ok {
		payload, err := s.decryptCallbackPayload(encrypted, initiatorPublicKey)
		if err != nil {
			s.logger.Warn("GTR callback payload cannot be decrypted", "error", err)
			writeGTRError(w, http.StatusOK, gtrCantDecrypt, "Fail to decrypt PII")
			return
		}
		forwarded := make(map[string]any, len(data))
		for key, value := range data {
			if key != "encryptedPayload" {
				forwarded[key] = value
			}
		}
		forwarded["payload"] = payload
		container["callbackData"] = forwarded
	}

	response, err := s.sumsub.ForwardCallback(r.Context(), container)
	if err != nil {
		var unreachable *sumsub.UnreachableError
		if errors.As(err, &unreachable) {
			s.logger.Error("Sumsub API is unreachable", "error", err)
			writeGTRError(w, http.StatusBadGateway, gtrCommonFail, "Sumsub API is unreachable")
			return
		}
		s.logger.Error("cannot forward the GTR callback", "error", err)
		writeGTRError(w, http.StatusInternalServerError, gtrCommonFail, "Internal error")
		return
	}
	if response.Status < 200 || response.Status >= 300 {
		s.logger.Error("Sumsub rejected the GTR callback", "status", response.Status)
		writeGTRError(w, http.StatusBadGateway, gtrCommonFail, "Sumsub responded HTTP "+http.StatusText(response.Status))
		return
	}

	answer, _ := response.Body.(map[string]any)
	if answerData, ok := answer["data"].(map[string]any); ok {
		if payload, hasPayload := answerData["payload"]; hasPayload {
			encrypted, err := s.encryptCallbackAnswer(payload, initiatorPublicKey)
			if err != nil {
				s.logger.Error("cannot encrypt the answer for GTR", "error", err)
				writeGTRError(w, http.StatusBadGateway, gtrCommonFail, "Cannot encrypt the answer")
				return
			}
			reEncrypted := make(map[string]any, len(answerData)+1)
			for key, value := range answerData {
				if key != "payload" {
					reEncrypted[key] = value
				}
			}
			reEncrypted["encryptedPayload"] = encrypted
			reEncrypted["initiatorPublicKey"] = gtr.PublicKeyBase64(s.keyPair)
			answer["data"] = reEncrypted
			response.Body = answer
		}
	}
	writeJSON(w, response.Status, response.Body)
}

func (s *server) decryptCallbackPayload(encrypted, initiatorPublicKey string) (any, error) {
	counterparty, err := gtr.ParseEd25519PublicKey(initiatorPublicKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := gtr.DecryptPayload(encrypted, s.keyPair, counterparty)
	if err != nil {
		return nil, err
	}
	var payload any
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, &gtr.CryptoError{Message: "decrypted payload is not JSON", Err: err}
	}
	return payload, nil
}

func (s *server) encryptCallbackAnswer(payload any, initiatorPublicKey string) (string, error) {
	counterparty, err := gtr.ParseEd25519PublicKey(initiatorPublicKey)
	if err != nil {
		return "", err
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return gtr.EncryptPayload(plaintext, s.keyPair, counterparty)
}

// writeGTRError answers in the GTR callback response shape, not the gateway's own error shape.
func writeGTRError(w http.ResponseWriter, status, verifyStatus int, message string) {
	writeJSON(w, status, map[string]any{"verifyStatus": verifyStatus, "verifyMessage": message})
}
