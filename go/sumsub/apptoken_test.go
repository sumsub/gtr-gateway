package sumsub

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	appSecret = "test-secret"
	ts        = "1756368000"
	path      = "/resources/api/tr/gtrGateway/callback"
	reference = "3f47251e6ae794e29899e421020c4c2dd676afed1dfaf2948fc5db2552fe3d81"
)

var appTokenBody = []byte(`{"callbackType":0,"requestId":"cb-1"}`)

func TestComputeAppTokenSignature(t *testing.T) {
	if got := ComputeAppTokenSignature(appSecret, ts, "post", path, appTokenBody); got != reference {
		t.Errorf("got %s, want %s", got, reference)
	}
	for name, got := range map[string]string{
		"other ts":     ComputeAppTokenSignature(appSecret, "1756368001", "POST", path, appTokenBody),
		"other method": ComputeAppTokenSignature(appSecret, ts, "GET", path, appTokenBody),
		"other path":   ComputeAppTokenSignature(appSecret, ts, "POST", path+"?x=1", appTokenBody),
		"other body":   ComputeAppTokenSignature(appSecret, ts, "POST", path, []byte("{}")),
	} {
		if got == reference {
			t.Errorf("%s must change the signature", name)
		}
	}
}

func TestSignRequest(t *testing.T) {
	request, _ := http.NewRequest(http.MethodPost, "https://api.sumsub.com"+path, strings.NewReader(string(appTokenBody)))
	SignRequest(request, Credentials{AppToken: "tok", AppSecret: appSecret}, appTokenBody, time.Unix(1756368000, 0))
	if request.Header.Get("X-App-Token") != "tok" || request.Header.Get("X-App-Access-Ts") != ts {
		t.Errorf("token/ts headers: %v", request.Header)
	}
	if got := request.Header.Get("X-App-Access-Sig"); got != reference {
		t.Errorf("signature header: got %s, want %s", got, reference)
	}
}
