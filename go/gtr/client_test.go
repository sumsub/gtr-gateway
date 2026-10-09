package gtr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

const (
	testVASPCode  = "my-vasp"
	testAccessKey = "access-key"
	testSecretKey = "secret-key"
	p12Password   = "changeit"
)

type testPKI struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test GTR CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testPKI{caCert: cert, caKey: key, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (p testPKI) issue(t *testing.T, serial int64, usage x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "test leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func (p testPKI) clientP12(t *testing.T) []byte {
	t.Helper()
	cert, key := p.issue(t, 3, x509.ExtKeyUsageClientAuth)
	data, err := pkcs12.Modern.Encode(key, cert, []*x509.Certificate{p.caCert}, p12Password)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type fakeGTRServer struct {
	logins      atomic.Int32
	expireFirst bool
	loginStatus int
	delay       time.Duration
}

func (f *fakeGTRServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	time.Sleep(f.delay)
	switch r.URL.Path {
	case "/api/login":
		var body struct{ VASPCode, AccessKey, SignedSecretKey string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		digest := sha512.Sum512([]byte(testSecretKey))
		if f.loginStatus != 0 || body.SignedSecretKey != hex.EncodeToString(digest[:]) || body.AccessKey != testAccessKey {
			w.WriteHeader(max(f.loginStatus, http.StatusUnauthorized))
			return
		}
		n := f.logins.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"jwt": "token-" + string(rune('0'+n))}})
	case "/api/vasp/detail":
		if f.expireFirst && r.Header.Get("Authorization") == "Bearer token-1" {
			_ = json.NewEncoder(w).Encode(map[string]any{"verifyStatus": loginExpiredVerifyStatus})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "token": r.Header.Get("Authorization"), "vaspCode": r.URL.Query().Get("vaspCode")})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func startServer(t *testing.T, pki testPKI, handler http.Handler) *httptest.Server {
	t.Helper()
	cert, key := pki.issue(t, 2, x509.ExtKeyUsageServerAuth)
	pool := x509.NewCertPool()
	pool.AddCert(pki.caCert)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func newTestClient(t *testing.T, server *httptest.Server, serverPKI testPKI, clientP12 []byte, timeout time.Duration) *Client {
	t.Helper()
	client, err := NewClient(ClientOptions{
		APIURL:                    server.URL,
		VASPCode:                  testVASPCode,
		AccessKey:                 testAccessKey,
		SecretKey:                 testSecretKey,
		ClientCertificateP12:      clientP12,
		ClientCertificatePassword: p12Password,
		CACertificatePEM:          serverPKI.caPEM,
		Timeout:                   timeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestLogsInOnceAndReusesTheToken(t *testing.T) {
	pki := newTestPKI(t)
	fake := &fakeGTRServer{}
	client := newTestClient(t, startServer(t, pki, fake), pki, pki.clientP12(t), 0)
	for range 2 {
		response, err := client.VASPDetail(context.Background(), "cp")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := response.Body.(map[string]any)
		if response.Status != http.StatusOK || body["token"] != "Bearer token-1" || body["vaspCode"] != "cp" {
			t.Fatalf("response %d %v", response.Status, response.Body)
		}
	}
	if fake.logins.Load() != 1 {
		t.Errorf("logged in %d times", fake.logins.Load())
	}
}

func TestLogsInAgainWhenTheTokenExpires(t *testing.T) {
	pki := newTestPKI(t)
	fake := &fakeGTRServer{expireFirst: true}
	client := newTestClient(t, startServer(t, pki, fake), pki, pki.clientP12(t), 0)
	response, err := client.VASPDetail(context.Background(), "cp")
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := response.Body.(map[string]any); body["token"] != "Bearer token-2" {
		t.Fatalf("response %v", response.Body)
	}
	if fake.logins.Load() != 2 {
		t.Errorf("logged in %d times", fake.logins.Load())
	}
}

func TestReportsARejectedLogin(t *testing.T) {
	pki := newTestPKI(t)
	client := newTestClient(t, startServer(t, pki, &fakeGTRServer{loginStatus: http.StatusForbidden}), pki, pki.clientP12(t), 0)
	_, err := client.VASPDetail(context.Background(), "cp")
	var loginErr *LoginError
	if !errors.As(err, &loginErr) || loginErr.Status != http.StatusForbidden {
		t.Fatalf("expected a login error, got %v", err)
	}
}

func TestFailsWithoutACertificateTheServerTrusts(t *testing.T) {
	serverPKI := newTestPKI(t)
	otherPKI := newTestPKI(t)
	client := newTestClient(t, startServer(t, serverPKI, &fakeGTRServer{}), serverPKI, otherPKI.clientP12(t), 0)
	_, err := client.VASPDetail(context.Background(), "cp")
	var unreachable *UnreachableError
	if !errors.As(err, &unreachable) {
		t.Fatalf("expected the TLS handshake to fail, got %v", err)
	}
}

func TestGivesUpAfterTheTimeout(t *testing.T) {
	pki := newTestPKI(t)
	client := newTestClient(t, startServer(t, pki, &fakeGTRServer{delay: 500 * time.Millisecond}), pki, pki.clientP12(t), 100*time.Millisecond)
	_, err := client.VASPDetail(context.Background(), "cp")
	var unreachable *UnreachableError
	if !errors.As(err, &unreachable) {
		t.Fatalf("expected a timeout, got %v", err)
	}
}
