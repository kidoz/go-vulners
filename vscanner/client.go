// Package vscanner provides a Go client for the Vulners VScanner vulnerability scanning API.
//
// VScanner allows you to manage vulnerability scanning projects, tasks, and results
// through the Vulners API. This package provides a type-safe Go interface to these
// capabilities.
//
// # Quick Start
//
// Create a client with your API key:
//
//	client, err := vscanner.NewClient("your-api-key")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// List projects:
//
//	projects, err := client.Project().List(ctx)
//
// Create a project:
//
//	project, err := client.Project().Create(ctx, &vscanner.ProjectRequest{
//	    Name:        "My Project",
//	    Description: "Security scanning project",
//	})
//
// # Services
//
// The client provides access to three main services:
//
//   - Project() - Manage scanning projects
//   - Task() - Create and run scanning tasks
//   - Result() - Access scan results and statistics
//
// # Rate Limiting
//
// The client includes built-in rate limiting that defaults to 5 requests/second
// with a burst of 10. You can customize this with WithRateLimit:
//
//	client, err := vscanner.NewClient("key", vscanner.WithRateLimit(10.0, 20))
//
// # Error Handling
//
// The package provides sentinel errors for common conditions:
//
//	if errors.Is(err, vscanner.ErrNotFound) {
//	    // Handle 404
//	}
//	if errors.Is(err, vscanner.ErrRateLimited) {
//	    // Handle 429
//	}
package vscanner

import (
	"bytes"
	"compress/gzip"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultBaseURL   = "https://vulners.com"
	defaultTimeout   = 30 * time.Second
	defaultUserAgent = "go-vulners-vscanner/1.1.2"

	// Default rate limit values
	defaultRateLimit = 5.0
	defaultBurst     = 10

	// Retry settings
	defaultMaxRetries = 3
	baseRetryDelay    = 500 * time.Millisecond
	maxRetryDelay     = 30 * time.Second

	// Response size limit (50MB)
	maxResponseSize = 50 * 1024 * 1024
)

// Client is the VScanner API client.
type Client struct {
	httpClient  *http.Client
	baseURL     string
	apiKey      string
	userAgent   string
	timeout     time.Duration
	maxRetries  int
	rateLimiter *rateLimiter
	rng         *lockedRand // thread-safe RNG for jitter

	// Lazy-initialized services
	projectOnce sync.Once
	project     *ProjectService
	taskOnce    sync.Once
	task        *TaskService
	resultOnce  sync.Once
	result      *ResultService
}

// lockedRand wraps rand.Rand with a mutex for thread-safe concurrent access.
type lockedRand struct {
	mu  sync.Mutex
	rng *rand.Rand
}

// Float64 returns a random float64 in [0.0, 1.0) in a thread-safe manner.
func (r *lockedRand) Float64() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rng.Float64()
}

// newLockedRand creates a new thread-safe RNG with a cryptographically secure seed.
func newLockedRand() *lockedRand {
	return &lockedRand{
		rng: rand.New(rand.NewSource(cryptoSeed())),
	}
}

// Option is a functional option for configuring the Client.
type Option func(*clientConfig)

type clientConfig struct {
	baseURL       string
	timeout       time.Duration
	maxRetries    int
	httpClient    *http.Client
	userAgent     string
	rateLimit     float64
	rateBurst     int
	proxyURL      string
	allowInsecure bool // allow HTTP URLs (for testing only)
}

// NewClient creates a new VScanner API client.
func NewClient(apiKey string, opts ...Option) (*Client, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("vscanner: API key is required")
	}

	cfg := &clientConfig{
		baseURL:    defaultBaseURL,
		timeout:    defaultTimeout,
		maxRetries: defaultMaxRetries,
		userAgent:  defaultUserAgent,
		rateLimit:  defaultRateLimit,
		rateBurst:  defaultBurst,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	// Validate base URL uses HTTPS (security: prevent API key leakage over HTTP)
	if !cfg.allowInsecure {
		parsedURL, err := url.Parse(cfg.baseURL)
		if err != nil {
			return nil, fmt.Errorf("vscanner: invalid base URL: %w", err)
		}
		isLocalhost := strings.HasPrefix(parsedURL.Host, "localhost") ||
			strings.HasPrefix(parsedURL.Host, "127.0.0.1") ||
			strings.HasPrefix(parsedURL.Host, "[::1]")
		if parsedURL.Scheme != "https" && !isLocalhost {
			return nil, fmt.Errorf("vscanner: base URL must use HTTPS to protect API key (use WithAllowInsecure for testing)")
		}
	}

	httpClient := cfg.httpClient
	if httpClient == nil {
		// Clone DefaultTransport to preserve standard defaults (proxy, timeouts, HTTP/2)
		transport := http.DefaultTransport.(*http.Transport).Clone()

		if cfg.proxyURL != "" {
			proxyURL, err := url.Parse(cfg.proxyURL)
			if err != nil {
				return nil, err
			}
			transport.Proxy = http.ProxyURL(proxyURL)
		}

		httpClient = &http.Client{
			Transport: transport,
			Timeout:   cfg.timeout,
			// Prevent API key from being forwarded to different hosts or HTTP
			CheckRedirect: makeCheckRedirect(cfg.baseURL),
		}
	}

	return &Client{
		httpClient:  httpClient,
		baseURL:     strings.TrimSuffix(cfg.baseURL, "/"),
		apiKey:      apiKey,
		userAgent:   cfg.userAgent,
		timeout:     cfg.timeout,
		maxRetries:  cfg.maxRetries,
		rateLimiter: newRateLimiter(cfg.rateLimit, cfg.rateBurst),
		rng:         newLockedRand(),
	}, nil
}

// cryptoSeed returns a cryptographically secure seed for the RNG.
func cryptoSeed() int64 {
	var seed int64
	if err := binary.Read(cryptorand.Reader, binary.LittleEndian, &seed); err != nil {
		// Fallback to time-based seed if crypto/rand fails (very rare)
		seed = time.Now().UnixNano()
	}
	return seed
}

// WithBaseURL sets a custom base URL for the API.
func WithBaseURL(baseURL string) Option {
	return func(c *clientConfig) {
		c.baseURL = baseURL
	}
}

// WithTimeout sets the HTTP request timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *clientConfig) {
		c.timeout = timeout
	}
}

// WithRetries sets the maximum number of retries for failed requests.
func WithRetries(maxRetries int) Option {
	return func(c *clientConfig) {
		c.maxRetries = maxRetries
	}
}

// WithHTTPClient sets a custom HTTP client.
//
// Note: When using a custom HTTP client, several built-in protections are bypassed:
//   - The WithTimeout option is ignored; configure timeouts directly on your http.Client.
//   - The WithProxy option is ignored; configure proxy on your http.Client's Transport.
//   - The default redirect protection (which prevents API key leakage to different hosts)
//     is bypassed. If your use case involves redirects, consider setting CheckRedirect
//     on your http.Client to prevent the API key from being sent to untrusted hosts.
//
// Example with custom redirect protection:
//
//	httpClient := &http.Client{
//	    Timeout: 60 * time.Second,
//	    CheckRedirect: func(req *http.Request, via []*http.Request) error {
//	        // Block redirects to prevent API key leakage
//	        return http.ErrUseLastResponse
//	    },
//	}
//	client, err := vscanner.NewClient("key", vscanner.WithHTTPClient(httpClient))
func WithHTTPClient(client *http.Client) Option {
	return func(c *clientConfig) {
		c.httpClient = client
	}
}

// WithUserAgent sets a custom User-Agent header.
func WithUserAgent(userAgent string) Option {
	return func(c *clientConfig) {
		c.userAgent = userAgent
	}
}

// WithProxy sets an HTTP proxy URL.
func WithProxy(proxyURL string) Option {
	return func(c *clientConfig) {
		c.proxyURL = proxyURL
	}
}

// WithRateLimit sets the rate limit (requests per second) and burst size.
func WithRateLimit(rate float64, burst int) Option {
	return func(c *clientConfig) {
		c.rateLimit = rate
		c.rateBurst = burst
	}
}

// WithAllowInsecure allows using HTTP instead of HTTPS.
// WARNING: This is insecure and should only be used for local testing.
// Using HTTP will expose your API key to network attackers.
func WithAllowInsecure() Option {
	return func(c *clientConfig) {
		c.allowInsecure = true
	}
}

// Project returns the ProjectService for managing projects.
func (c *Client) Project() *ProjectService {
	c.projectOnce.Do(func() {
		c.project = &ProjectService{client: c}
	})
	return c.project
}

// Task returns the TaskService for managing tasks.
func (c *Client) Task() *TaskService {
	c.taskOnce.Do(func() {
		c.task = &TaskService{client: c}
	})
	return c.task
}

// Result returns the ResultService for managing results.
func (c *Client) Result() *ResultService {
	c.resultOnce.Do(func() {
		c.result = &ResultService{client: c}
	})
	return c.result
}

// License represents a VScanner license.
type License struct {
	ID         string `json:"id,omitempty"`
	Type       string `json:"type,omitempty"`
	ValidUntil *Time  `json:"validUntil,omitempty"`
	Hosts      int    `json:"hosts,omitempty"`
}

// GetLicenses returns the available VScanner licenses.
func (c *Client) GetLicenses(ctx context.Context) ([]License, error) {
	var licenses []License
	if err := c.doGet(ctx, "/api/v3/vscanner/licenses", nil, &licenses); err != nil {
		return nil, err
	}
	return licenses, nil
}

// do performs an HTTP request with retry logic.
func (c *Client) do(ctx context.Context, method, path string, body, result interface{}) error {
	var attempt int
	for {
		// Wait for rate limit with context support
		if c.rateLimiter != nil {
			if err := c.rateLimiter.waitContext(ctx); err != nil {
				return err
			}
		}

		err := c.doOnce(ctx, method, path, body, result)
		if err == nil {
			return nil
		}

		if !c.shouldRetry(err, attempt) {
			return err
		}

		attempt++

		// Use Retry-After if provided by the server, otherwise use exponential backoff
		delay := c.backoffDelay(attempt)
		var retryErr *retryableError
		if errors.As(err, &retryErr) && retryErr.retryAfter > 0 {
			delay = retryErr.retryAfter
			// Cap the server-suggested delay to maxRetryDelay
			if delay > maxRetryDelay {
				delay = maxRetryDelay
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

func (c *Client) doOnce(ctx context.Context, method, path string, body, result interface{}) error {
	reqURL := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return c.handleResponse(resp, result)
}

func (c *Client) handleResponse(resp *http.Response, result interface{}) error {
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer func() { _ = gzReader.Close() }()
		reader = gzReader
	}

	// Read response body with size limit (read one extra byte to detect truncation)
	limitedReader := &io.LimitedReader{R: reader, N: maxResponseSize + 1}
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	if limitedReader.N == 0 {
		return fmt.Errorf("vscanner: response body exceeds maximum size of %d bytes", maxResponseSize)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		message := "request failed"
		if json.Unmarshal(bodyBytes, &errResp) == nil && errResp.Error != "" {
			message = errResp.Error
		}
		apiErr := &APIError{StatusCode: resp.StatusCode, Message: message}

		// Parse Retry-After header if present (for 429 and 503 responses)
		if retryAfter := parseRetryAfter(resp.Header.Get("Retry-After")); retryAfter > 0 {
			return &retryableError{err: apiErr, retryAfter: retryAfter}
		}
		return apiErr
	}

	var apiResp struct {
		Result string          `json:"result"`
		Data   json.RawMessage `json:"data,omitempty"`
		Error  string          `json:"error,omitempty"`
	}

	if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
		if result != nil {
			return json.Unmarshal(bodyBytes, result)
		}
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if apiResp.Result != "OK" && apiResp.Result != "" {
		if apiResp.Error != "" {
			return fmt.Errorf("vscanner: API error: %s", apiResp.Error)
		}
		return fmt.Errorf("vscanner: request failed with result: %s", apiResp.Result)
	}

	if result != nil && len(apiResp.Data) > 0 {
		if err := json.Unmarshal(apiResp.Data, result); err != nil {
			return fmt.Errorf("failed to unmarshal response data: %w", err)
		}
	}

	return nil
}

// Sentinel errors for common error conditions.
var (
	// ErrNotFound is returned when a requested resource is not found.
	ErrNotFound = errors.New("vscanner: resource not found")

	// ErrRateLimited is returned when the rate limit has been exceeded.
	ErrRateLimited = errors.New("vscanner: rate limit exceeded")

	// ErrUnauthorized is returned when the API key is invalid or expired.
	ErrUnauthorized = errors.New("vscanner: unauthorized - invalid or expired API key")

	// ErrBadRequest is returned when the request is malformed.
	ErrBadRequest = errors.New("vscanner: bad request")

	// ErrServerError is returned when the server returns a 5xx error.
	ErrServerError = errors.New("vscanner: server error")
)

// APIError represents an error response from the VScanner API.
type APIError struct {
	StatusCode int
	Message    string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return fmt.Sprintf("vscanner: API error (status %d): %s", e.StatusCode, e.Message)
}

// Is implements errors.Is for APIError.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.StatusCode == 404
	case ErrRateLimited:
		return e.StatusCode == 429
	case ErrUnauthorized:
		return e.StatusCode == 401 || e.StatusCode == 403
	case ErrBadRequest:
		return e.StatusCode == 400
	case ErrServerError:
		return e.StatusCode >= 500 && e.StatusCode < 600
	}
	return false
}

// retryableError wraps an error with a suggested retry delay from Retry-After header.
type retryableError struct {
	err        error
	retryAfter time.Duration
}

func (e *retryableError) Error() string {
	return e.err.Error()
}

func (e *retryableError) Unwrap() error {
	return e.err
}

// parseRetryAfter parses the Retry-After header value.
// It supports both delta-seconds format (e.g., "120") and HTTP-date format.
func parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}

	// Try parsing as seconds first (most common)
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}

	// Try parsing as HTTP-date (RFC 1123 format)
	if t, err := http.ParseTime(value); err == nil {
		delay := time.Until(t)
		if delay > 0 {
			return delay
		}
	}

	return 0
}

func (c *Client) shouldRetry(err error, attempt int) bool {
	if attempt >= c.maxRetries {
		return false
	}

	// Check for typed error
	var vsErr *APIError
	if errors.As(err, &vsErr) {
		return vsErr.StatusCode == 429 || vsErr.StatusCode >= 500
	}

	// Fallback: retry on network errors (but not context cancellation)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Check for temporary network errors
	var netErr interface{ Temporary() bool }
	if errors.As(err, &netErr) && netErr.Temporary() {
		return true
	}

	return false
}

func (c *Client) backoffDelay(attempt int) time.Duration {
	delay := time.Duration(float64(baseRetryDelay) * math.Pow(2, float64(attempt-1)))
	if delay > maxRetryDelay {
		delay = maxRetryDelay
	}
	// Use per-client RNG for jitter to avoid global lock contention
	jitter := time.Duration(c.rng.Float64() * 0.25 * float64(delay))
	return delay + jitter
}

func (c *Client) doGet(ctx context.Context, path string, params map[string]string, result interface{}) error {
	if len(params) > 0 {
		values := url.Values{}
		for k, v := range params {
			values.Set(k, v)
		}
		path = path + "?" + values.Encode()
	}
	return c.do(ctx, http.MethodGet, path, nil, result)
}

func (c *Client) doPost(ctx context.Context, path string, body, result interface{}) error {
	return c.do(ctx, http.MethodPost, path, body, result)
}

func (c *Client) doPut(ctx context.Context, path string, body, result interface{}) error {
	return c.do(ctx, http.MethodPut, path, body, result)
}

// doGetRaw performs a GET request and returns raw bytes (for binary responses like PDF/CSV exports).
func (c *Client) doGetRaw(ctx context.Context, path string, params map[string]string) ([]byte, error) {
	if len(params) > 0 {
		values := url.Values{}
		for k, v := range params {
			values.Set(k, v)
		}
		path = path + "?" + values.Encode()
	}

	reqURL := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept-Encoding", "gzip")

	// Wait for rate limit with context support
	if c.rateLimiter != nil {
		if err := c.rateLimiter.waitContext(ctx); err != nil {
			return nil, err
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer func() { _ = gzReader.Close() }()
		reader = gzReader
	}

	// Limit response size to 100MB for binary responses (read one extra byte to detect truncation)
	const maxBinaryResponseSize = 100 * 1024 * 1024
	limitedReader := &io.LimitedReader{R: reader, N: maxBinaryResponseSize + 1}
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if limitedReader.N == 0 {
		return nil, fmt.Errorf("vscanner: response body exceeds maximum size of %d bytes", maxBinaryResponseSize)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("vscanner: API error (status %d): %s", resp.StatusCode, string(data))
	}

	return data, nil
}

// rateLimiter implements a simple token bucket rate limiter.
type rateLimiter struct {
	mu         sync.Mutex
	rate       float64
	burst      int
	tokens     float64
	lastUpdate time.Time
}

const minRateLimiterRate = 0.001

func newRateLimiter(rate float64, burst int) *rateLimiter {
	if rate < minRateLimiterRate {
		rate = minRateLimiterRate
	}
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

// waitContext blocks until a token is available or the context is cancelled.
func (r *rateLimiter) waitContext(ctx context.Context) error {
	r.mu.Lock()

	for {
		r.refill()

		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return nil
		}

		// Guard against rate being too small
		rate := r.rate
		if rate < minRateLimiterRate {
			rate = minRateLimiterRate
		}
		waitTime := time.Duration((1 - r.tokens) / rate * float64(time.Second))

		// Release lock while sleeping, then re-check
		r.mu.Unlock()

		timer := time.NewTimer(waitTime)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}

		r.mu.Lock()
	}
}

func (r *rateLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(r.lastUpdate).Seconds()
	r.tokens += elapsed * r.rate
	if r.tokens > float64(r.burst) {
		r.tokens = float64(r.burst)
	}
	if r.tokens < 0 {
		r.tokens = 0
	}
	r.lastUpdate = now
}

// makeCheckRedirect creates a CheckRedirect function that prevents the API key
// from being forwarded to a different host or downgraded to HTTP.
func makeCheckRedirect(baseURL string) func(*http.Request, []*http.Request) error {
	parsedBase, _ := url.Parse(baseURL)
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		// Block redirects that change the host
		if parsedBase != nil && req.URL.Host != parsedBase.Host {
			return fmt.Errorf("vscanner: refusing to follow redirect to different host: %s", req.URL.Host)
		}
		// Block redirects that downgrade from HTTPS to HTTP
		if parsedBase != nil && parsedBase.Scheme == "https" && req.URL.Scheme == "http" {
			return fmt.Errorf("vscanner: refusing to follow redirect from HTTPS to HTTP")
		}
		return nil
	}
}

// Time is a custom time type that handles various time formats from the API.
type Time struct {
	time.Time
}

// UnmarshalJSON implements json.Unmarshaler for Time.
func (t *Time) UnmarshalJSON(data []byte) error {
	// Handle null
	if string(data) == "null" {
		return nil
	}

	// Remove quotes
	s := string(data)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}

	// Try various formats
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02",
		"2006-01-02 15:04:05",
	}

	var err error
	for _, format := range formats {
		t.Time, err = time.Parse(format, s)
		if err == nil {
			return nil
		}
	}

	// Try parsing as Unix timestamp (milliseconds)
	var ms int64
	if err := json.Unmarshal(data, &ms); err == nil {
		t.Time = time.UnixMilli(ms)
		return nil
	}

	return err
}

// MarshalJSON implements json.Marshaler for Time.
func (t Time) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(t.Format(time.RFC3339))
}
