// Package gtr talks to the GTR API and implements its PII envelope.
package gtr

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// GTR API origins: a Sumsub Sandbox gateway talks to UAT, a production gateway to production.
const (
	ProductionAPIURL = "https://platform.globaltravelrule.com"
	UATAPIURL        = "https://uat-platform.globaltravelrule.com"
)

// DefaultTimeout bounds a GTR call and stays below the 20 seconds Sumsub waits for the gateway.
const DefaultTimeout = 15 * time.Second

const (
	loginExpiredVerifyStatus = 100014
	maxResponseBytes         = 10 << 20
)

// Response is a GTR answer, returned to Sumsub unchanged.
type Response struct {
	Status int
	Body   any // decoded JSON, or the raw text when the body is not JSON
}

// API is the subset of GTR the gateway proxies. The routes depend on nothing else.
type API interface {
	VASPDetail(ctx context.Context, vaspCode string) (Response, error)
	AutoAddressVASPDetection(ctx context.Context, body any) (Response, error)
	OneStep(ctx context.Context, body map[string]any) (Response, error)
	SubmitTxID(ctx context.Context, body any) (Response, error)
	EndTravelRule(ctx context.Context, body any) (Response, error)
}

// UnreachableError means GTR did not answer (network, TLS, timeout); the gateway answers 502.
type UnreachableError struct{ Err error }

func (e *UnreachableError) Error() string { return "GTR API is unreachable: " + e.Err.Error() }
func (e *UnreachableError) Unwrap() error { return e.Err }

// LoginError means GTR rejected the credentials; the gateway answers 502.
type LoginError struct{ Status int }

func (e *LoginError) Error() string { return fmt.Sprintf("GTR login failed with HTTP %d", e.Status) }

// ClientOptions configures the GTR client.
type ClientOptions struct {
	// APIURL is the GTR API origin without a path: ProductionAPIURL or UATAPIURL.
	APIURL    string
	VASPCode  string
	AccessKey string
	SecretKey string
	// ClientCertificateP12 is the PKCS#12 client certificate issued by GTR for the API key.
	ClientCertificateP12      []byte
	ClientCertificatePassword string
	// CACertificatePEM is only needed when the GTR environment uses a private CA.
	CACertificatePEM []byte
	// Timeout bounds every GTR call; zero means DefaultTimeout.
	Timeout time.Duration
}

// Client is a GTR API client with mutual TLS, a cached JWT and one re-login when it expires.
type Client struct {
	http    *http.Client
	baseURL string
	options ClientOptions

	mu    sync.Mutex
	token string
}

// NewClient builds the TLS configuration from the PKCS#12 certificate and returns a ready client.
func NewClient(options ClientOptions) (*Client, error) {
	parsed, err := url.Parse(options.APIURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("GTR API URL must be an absolute URL")
	}

	key, certificate, chain, err := pkcs12.DecodeChain(options.ClientCertificateP12, options.ClientCertificatePassword)
	if err != nil {
		return nil, fmt.Errorf("cannot read the GTR client certificate: %w", err)
	}
	tlsCertificate := tls.Certificate{PrivateKey: key, Certificate: [][]byte{certificate.Raw}}
	for _, ca := range chain {
		tlsCertificate.Certificate = append(tlsCertificate.Certificate, ca.Raw)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{tlsCertificate}, MinVersion: tls.VersionTLS12}
	if len(options.CACertificatePEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(options.CACertificatePEM) {
			return nil, errors.New("GTR CA certificate is not valid PEM")
		}
		tlsConfig.RootCAs = pool
	}

	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		http:    &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: tlsConfig}},
		baseURL: strings.TrimRight(options.APIURL, "/"),
		options: options,
	}, nil
}

func (c *Client) VASPDetail(ctx context.Context, vaspCode string) (Response, error) {
	return c.call(ctx, http.MethodGet, "/api/vasp/detail?vaspCode="+url.QueryEscape(vaspCode), nil)
}

func (c *Client) AutoAddressVASPDetection(ctx context.Context, body any) (Response, error) {
	return c.call(ctx, http.MethodPost, "/api/verify/v2/auto_address_vasp_detection", body)
}

func (c *Client) OneStep(ctx context.Context, body map[string]any) (Response, error) {
	return c.call(ctx, http.MethodPost, "/api/verify/v2/one_step", body)
}

func (c *Client) SubmitTxID(ctx context.Context, body any) (Response, error) {
	return c.call(ctx, http.MethodPost, "/api/verify/tx/submit", body)
}

func (c *Client) EndTravelRule(ctx context.Context, body any) (Response, error) {
	return c.call(ctx, http.MethodPost, "/api/verify/v2/end", body)
}

func (c *Client) call(ctx context.Context, method, path string, body any) (Response, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return Response{}, err
	}
	status, raw, err := c.send(ctx, method, path, body, token)
	if err != nil {
		return Response{}, err
	}
	response := Response{Status: status, Body: parseJSON(raw)}
	if !isLoginExpired(response) {
		return response, nil
	}

	c.resetToken()
	token, err = c.getToken(ctx)
	if err != nil {
		return Response{}, err
	}
	status, raw, err = c.send(ctx, method, path, body, token)
	if err != nil {
		return Response{}, err
	}
	return Response{Status: status, Body: parseJSON(raw)}, nil
}

func (c *Client) send(ctx context.Context, method, path string, body any, token string) (int, []byte, error) {
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("cannot encode the GTR request: %w", err)
		}
		payload = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, payload)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return 0, nil, &UnreachableError{Err: err}
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, &UnreachableError{Err: err}
	}
	return response.StatusCode, raw, nil
}

func (c *Client) getToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" {
		return c.token, nil
	}
	token, err := c.login(ctx)
	if err != nil {
		return "", err
	}
	c.token = token
	return token, nil
}

func (c *Client) resetToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = ""
}

func (c *Client) login(ctx context.Context) (string, error) {
	signedSecretKey := sha512.Sum512([]byte(c.options.SecretKey))
	status, raw, err := c.send(ctx, http.MethodPost, "/api/login", map[string]string{
		"vaspCode":        c.options.VASPCode,
		"accessKey":       c.options.AccessKey,
		"signedSecretKey": hex.EncodeToString(signedSecretKey[:]),
	}, "")
	if err != nil {
		return "", err
	}
	var parsed struct {
		Data struct {
			JWT string `json:"jwt"`
		} `json:"data"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &parsed) != nil || parsed.Data.JWT == "" {
		return "", &LoginError{Status: status}
	}
	return parsed.Data.JWT, nil
}

func isLoginExpired(response Response) bool {
	if response.Status == http.StatusUnauthorized {
		return true
	}
	body, ok := response.Body.(map[string]any)
	if !ok {
		return false
	}
	verifyStatus, ok := body["verifyStatus"].(float64)
	return ok && int(verifyStatus) == loginExpiredVerifyStatus
}

func parseJSON(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return string(raw)
	}
	return value
}
