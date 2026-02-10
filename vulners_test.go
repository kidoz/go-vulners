package vulners

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		apiKey  string
		opts    []Option
		wantErr bool
	}{
		{
			name:    "valid API key",
			apiKey:  "test-api-key",
			wantErr: false,
		},
		{
			name:    "empty API key",
			apiKey:  "",
			wantErr: true,
		},
		{
			name:   "with options",
			apiKey: "test-api-key",
			opts: []Option{
				WithTimeout(60 * time.Second),
				WithRetries(5),
				WithUserAgent("test-agent"),
			},
			wantErr: false,
		},
		{
			name:   "HTTP URL rejected without AllowInsecure",
			apiKey: "test-api-key",
			opts: []Option{
				WithBaseURL("http://vulners.example.com"),
			},
			wantErr: true,
		},
		{
			name:   "HTTP URL allowed with AllowInsecure",
			apiKey: "test-api-key",
			opts: []Option{
				WithBaseURL("http://vulners.example.com"),
				WithAllowInsecure(),
			},
			wantErr: false,
		},
		{
			name:   "localhost HTTP allowed without AllowInsecure",
			apiKey: "test-api-key",
			opts: []Option{
				WithBaseURL("http://localhost:8080"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.apiKey, tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewClient() returned nil client")
			}
		})
	}
}

func TestClient_Search(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		resp := apiResponse{
			Result: "OK",
			Data: json.RawMessage(`{
				"search": [
					{
						"id": "CVE-2021-44228",
						"title": "Log4Shell",
						"type": "cve",
						"cvss": {"score": 10.0}
					}
				],
				"total": 1
			}`),
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient("test-key",
		WithBaseURL(server.URL),
		WithAllowInsecure(),
		WithRateLimit(100, 100),
	)
	if err != nil {
		t.Fatal(err)
	}

	results, err := client.Search().SearchBulletins(context.Background(), "log4j")
	if err != nil {
		t.Fatal(err)
	}

	if results.Total != 1 {
		t.Errorf("expected total=1, got %d", results.Total)
	}

	if len(results.Bulletins) != 1 {
		t.Errorf("expected 1 bulletin, got %d", len(results.Bulletins))
	}

	if results.Bulletins[0].ID != "CVE-2021-44228" {
		t.Errorf("expected ID=CVE-2021-44228, got %s", results.Bulletins[0].ID)
	}
}

func TestClient_GetBulletin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := apiResponse{
			Result: "OK",
			Data: json.RawMessage(`{
				"documents": {
					"CVE-2021-44228": {
						"id": "CVE-2021-44228",
						"title": "Log4Shell",
						"description": "Apache Log4j2 vulnerability"
					}
				}
			}`),
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient("test-key",
		WithBaseURL(server.URL),
		WithAllowInsecure(),
		WithRateLimit(100, 100),
	)
	if err != nil {
		t.Fatal(err)
	}

	bulletin, err := client.Search().GetBulletin(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatal(err)
	}

	if bulletin.ID != "CVE-2021-44228" {
		t.Errorf("expected ID=CVE-2021-44228, got %s", bulletin.ID)
	}

	if bulletin.Title != "Log4Shell" {
		t.Errorf("expected Title=Log4Shell, got %s", bulletin.Title)
	}
}

func TestClient_Audit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := apiResponse{
			Result: "OK",
			Data: json.RawMessage(`{
				"cvelist": ["CVE-2021-3711", "CVE-2021-3712"],
				"cvss": {"score": 9.8, "severity": "CRITICAL"},
				"cumulativeFix": "openssl 1.1.1l"
			}`),
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient("test-key",
		WithBaseURL(server.URL),
		WithAllowInsecure(),
		WithRateLimit(100, 100),
	)
	if err != nil {
		t.Fatal(err)
	}

	packages := []string{"openssl 1.1.1f-1ubuntu2"}
	result, err := client.Audit().LinuxAudit(context.Background(), "Ubuntu", "20.04", packages)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.CVEList) != 2 {
		t.Errorf("expected 2 CVEs, got %d", len(result.CVEList))
	}

	if result.CVSSScore != 9.8 {
		t.Errorf("expected CVSS=9.8, got %f", result.CVSSScore)
	}
}

func TestAPIError(t *testing.T) {
	err := NewAPIError(404, "not found", "NOT_FOUND")

	if err.StatusCode != 404 {
		t.Errorf("expected StatusCode=404, got %d", err.StatusCode)
	}

	if err.Message != "not found" {
		t.Errorf("expected Message='not found', got %s", err.Message)
	}

	// Test Is() implementation
	if !err.Is(ErrNotFound) {
		t.Error("expected err.Is(ErrNotFound) to be true")
	}

	if err.Is(ErrRateLimited) {
		t.Error("expected err.Is(ErrRateLimited) to be false")
	}

	// Test error string
	errStr := err.Error()
	if errStr == "" {
		t.Error("expected non-empty error string")
	}
}

func TestTime_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "RFC3339",
			input:   `"2021-12-09T12:00:00Z"`,
			wantErr: false,
		},
		{
			name:    "date only",
			input:   `"2021-12-09"`,
			wantErr: false,
		},
		{
			name:    "null",
			input:   `null`,
			wantErr: false,
		},
		{
			name:    "timestamp",
			input:   `1639051200000`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tm Time
			err := json.Unmarshal([]byte(tt.input), &tm)
			if (err != nil) != tt.wantErr {
				t.Errorf("Time.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	loc, err := time.LoadLocation("GMT")
	require.NoError(t, err)

	tests := []struct {
		name     string
		value    string
		expected time.Duration
	}{
		{
			name:     "empty value",
			value:    "",
			expected: 0,
		},
		{
			name:     "delta-seconds",
			value:    "120",
			expected: 2 * time.Minute,
		},
		{
			name:     "invalid delta-seconds",
			value:    "abc",
			expected: 0,
		},
		{
			name:     "negative delta-seconds",
			value:    "-10",
			expected: 0,
		},
		{
			name:     "http-date in the future",
			value:    time.Now().In(loc).Add(5 * time.Minute).Format(time.RFC1123),
			expected: 5 * time.Minute,
		},
		{
			name:     "http-date in the past",
			value:    time.Now().In(loc).Add(-5 * time.Minute).Format(time.RFC1123),
			expected: 0,
		},
		{
			name:     "invalid http-date",
			value:    "not a date",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := parseRetryAfter(tt.value)
			// Allow for a small delta due to timing issues with http-date
			if tt.name == "http-date in the future" {
				assert.InDelta(t, tt.expected, d, float64(time.Second))
			} else {
				assert.Equal(t, tt.expected, d)
			}
		})
	}
}

func TestShouldRetry(t *testing.T) {
	transport := &transport{maxRetries: defaultMaxRetries}

	tests := []struct {
		name     string
		err      error
		attempt  int
		expected bool
	}{
		{
			name:     "no error",
			err:      nil,
			attempt:  0,
			expected: false,
		},
		{
			name:     "max retries reached",
			err:      NewAPIError(500, "server error", ""),
			attempt:  defaultMaxRetries,
			expected: false,
		},
		{
			name:     "context canceled",
			err:      context.Canceled,
			attempt:  0,
			expected: false,
		},
		{
			name:     "context deadline exceeded",
			err:      context.DeadlineExceeded,
			attempt:  0,
			expected: false,
		},
		{
			name:     "rate limit error",
			err:      NewAPIError(429, "rate limit", ""),
			attempt:  1,
			expected: true,
		},
		{
			name:     "server error",
			err:      NewAPIError(500, "internal server error", ""),
			attempt:  1,
			expected: true,
		},
		{
			name:     "client error (not retryable)",
			err:      NewAPIError(400, "bad request", ""),
			attempt:  1,
			expected: false,
		},
		{
			name:     "temporary network error",
			err:      &url.Error{Err: tempErr(true)},
			attempt:  1,
			expected: true,
		},
		{
			name:     "non-temporary network error",
			err:      &url.Error{Err: tempErr(false)},
			attempt:  1,
			expected: false,
		},
		{
			name:     "timeout error",
			err:      &url.Error{Err: timeoutErr(true)},
			attempt:  1,
			expected: true,
		},
		{
			name:     "other error",
			err:      fmt.Errorf("some other error"),
			attempt:  1,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := transport.shouldRetry(tt.err, tt.attempt)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestBackoffDelay(t *testing.T) {
	transport := &transport{rng: newLockedRand()}
	minDelay := time.Duration(float64(baseRetryDelay) * 1.0)
	maxDelay := time.Duration(float64(baseRetryDelay) * 1.25)

	delay := transport.backoffDelay(1)
	assert.True(t, delay >= minDelay && delay <= maxDelay, "delay for attempt 1 is out of range")

	minDelay = time.Duration(float64(baseRetryDelay) * 2.0)
	maxDelay = time.Duration(float64(baseRetryDelay) * 2.0 * 1.25)

	delay = transport.backoffDelay(2)
	assert.True(t, delay >= minDelay && delay <= maxDelay, "delay for attempt 2 is out of range")
}

// tempErr is a helper to create an error that implements the Temporary() bool interface.
type tempErr bool

func (e tempErr) Error() string   { return "temporary error" }
func (e tempErr) Temporary() bool { return bool(e) }

// timeoutErr is a helper to create an error that implements the Timeout() bool interface.
type timeoutErr bool

func (e timeoutErr) Error() string   { return "timeout error" }
func (e timeoutErr) Timeout() bool   { return bool(e) }
func (e timeoutErr) Temporary() bool { return bool(e) }
