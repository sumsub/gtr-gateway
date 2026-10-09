package sumsub

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Credentials is the app token issued in Sumsub dashboard → Marketplace → GTR → "Generate API token".
type Credentials struct {
	AppToken  string
	AppSecret string
}

// ComputeAppTokenSignature returns the Sumsub API signature: hex HMAC-SHA256 of
// ts + METHOD + path + body, where path includes the /resources prefix and the query string.
func ComputeAppTokenSignature(appSecret, ts, method, path string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(appSecret))
	mac.Write([]byte(ts))
	mac.Write([]byte(strings.ToUpper(method)))
	mac.Write([]byte(path))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// SignRequest adds the X-App-Token, X-App-Access-Ts and X-App-Access-Sig headers.
func SignRequest(request *http.Request, credentials Credentials, body []byte, now time.Time) {
	ts := strconv.FormatInt(now.Unix(), 10)
	request.Header.Set("X-App-Token", credentials.AppToken)
	request.Header.Set("X-App-Access-Ts", ts)
	request.Header.Set("X-App-Access-Sig", ComputeAppTokenSignature(credentials.AppSecret, ts, request.Method, request.URL.RequestURI(), body))
}
