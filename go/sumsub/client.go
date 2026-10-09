package sumsub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CallbackPath is the Sumsub API endpoint that accepts forwarded GTR callbacks.
const CallbackPath = "/resources/api/tr/gtrGateway/callback"

// DefaultTimeout bounds a call to Sumsub.
const DefaultTimeout = 15 * time.Second

const maxResponseBytes = 10 << 20

// Response is a Sumsub answer, returned to GTR after re-encryption.
type Response struct {
	Status int
	Body   any
}

// CallbackAPI forwards GTR callbacks to Sumsub.
type CallbackAPI interface {
	ForwardCallback(ctx context.Context, body any) (Response, error)
}

// UnreachableError means Sumsub did not answer; the gateway tells GTR verifyStatus 100001.
type UnreachableError struct{ Err error }

func (e *UnreachableError) Error() string { return "Sumsub API is unreachable: " + e.Err.Error() }
func (e *UnreachableError) Unwrap() error { return e.Err }

// Client forwards GTR callbacks to the Sumsub API, signed with the app token.
type Client struct {
	http        *http.Client
	baseURL     string
	credentials Credentials
	now         func() time.Time
}

// ClientOptions configures the client that forwards GTR callbacks to Sumsub.
type ClientOptions struct {
	// APIURL is the Sumsub API origin without a path, e.g. https://api.sumsub.com.
	APIURL string
	Credentials
	// Timeout bounds a call to Sumsub; zero means DefaultTimeout.
	Timeout time.Duration
}

// NewClient validates the API URL and the app token credentials.
func NewClient(options ClientOptions) (*Client, error) {
	parsed, err := url.Parse(options.APIURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("the Sumsub API URL must be an absolute URL")
	}
	if options.AppToken == "" || options.AppSecret == "" {
		return nil, errors.New("the Sumsub app token and app secret are required")
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		http:        &http.Client{Timeout: timeout},
		baseURL:     strings.TrimRight(options.APIURL, "/"),
		credentials: options.Credentials,
		now:         time.Now,
	}, nil
}

func (c *Client) ForwardCallback(ctx context.Context, body any) (Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return Response{}, fmt.Errorf("cannot encode the callback: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+CallbackPath, bytes.NewReader(data))
	if err != nil {
		return Response{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	SignRequest(request, c.credentials, data, c.now())

	response, err := c.http.Do(request)
	if err != nil {
		return Response{}, &UnreachableError{Err: err}
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return Response{}, &UnreachableError{Err: err}
	}
	return Response{Status: response.StatusCode, Body: parseJSON(raw)}, nil
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
