package vulners

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
	"mime/multipart"
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
	defaultUserAgent = "go-vulners/1.1.0"

	// Default rate limit values (conservative defaults)
	defaultRateLimit = 5.0 // requests per second
	defaultBurst     = 10  // max burst

	// Retry settings
	defaultMaxRetries = 3
	baseRetryDelay    = 500 * time.Millisecond
	maxRetryDelay     = 30 * time.Second

	// Response size limit (50MB)
	maxResponseSize = 50 * 1024 * 1024
)

// httpClient performs HTTP requests. Extracted for testing.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// transport handles the HTTP communication with the Vulners API.
type transport struct {
	httpClient  httpClient
	baseURL     string
	apiKey      string
	userAgent   string
	maxRetries  int
	rateLimiter *RateLimiter
	rng         *lockedRand // thread-safe RNG for jitter
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

// newTransport creates a new transport with the given configuration.
func newTransport(httpClient httpClient, baseURL, apiKey, userAgent string, maxRetries int, rateLimiter *RateLimiter) *transport {
	return &transport{
		httpClient:  httpClient,
		baseURL:     strings.TrimSuffix(baseURL, "/"),
		apiKey:      apiKey,
		userAgent:   userAgent,
		maxRetries:  maxRetries,
		rateLimiter: rateLimiter,
		rng:         newLockedRand(),
	}
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

// do performs an HTTP request and decodes the response.
func (t *transport) do(ctx context.Context, method, path string, body, result any) error {
	var attempt int
	for {
		// Wait for rate limit with context support
		if t.rateLimiter != nil {
			if err := t.rateLimiter.WaitContext(ctx); err != nil {
				return err
			}
		}

		err := t.doOnce(ctx, method, path, body, result)
		if err == nil {
			return nil
		}

		// Check if we should retry
		if !t.shouldRetry(err, attempt) {
			return err
		}

		attempt++

		// Use Retry-After if provided by the server, otherwise use exponential backoff
		delay := t.backoffDelay(attempt)
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
			// Continue to retry
		}
	}
}

// doOnce performs a single HTTP request attempt.
func (t *transport) doOnce(ctx context.Context, method, path string, body, result any) error {
	// Build URL
	reqURL := t.baseURL + path

	// Prepare request body
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if t.apiKey != "" {
		req.Header.Set("X-Api-Key", t.apiKey)
	}
	req.Header.Set("User-Agent", t.userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Perform request
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Update rate limiter from headers
	t.updateRateLimitFromHeaders(resp.Header)

	// Handle response
	return t.handleResponse(resp, result)
}

// handleResponse processes the HTTP response and extracts the result.
func (t *transport) handleResponse(resp *http.Response, result any) error {
	// Handle compressed response
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
		return fmt.Errorf("vulners: response body exceeds maximum size of %d bytes", maxResponseSize)
	}

	// Check for HTTP errors
	if resp.StatusCode >= 400 {
		return t.handleErrorResponse(resp.StatusCode, bodyBytes, resp.Header)
	}

	// Handle empty response body (e.g., 204 No Content)
	if len(bodyBytes) == 0 {
		return nil
	}

	// Parse API response wrapper
	var apiResp apiResponse
	if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
		// If it's not a wrapped response, try to decode directly
		if result != nil {
			return json.Unmarshal(bodyBytes, result)
		}
		// Empty or non-JSON response with no expected result is OK
		return nil
	}

	// Check for API-level errors
	if apiResp.Result != "OK" && apiResp.Result != "" {
		if apiResp.Error != "" {
			return NewAPIError(resp.StatusCode, apiResp.Error, apiResp.Result)
		}
		return NewAPIError(resp.StatusCode, "request failed: "+apiResp.Result, "")
	}

	// Decode data into result
	if result != nil && len(apiResp.Data) > 0 {
		if err := json.Unmarshal(apiResp.Data, result); err != nil {
			return fmt.Errorf("failed to unmarshal response data: %w", err)
		}
	}

	return nil
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

// handleErrorResponse converts HTTP errors to appropriate error types.
func (t *transport) handleErrorResponse(statusCode int, body []byte, headers http.Header) error {
	// Try to parse error message from body
	var errResp struct {
		Error string `json:"error"`
	}
	message := "request failed"
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		message = errResp.Error
	}

	apiErr := NewAPIError(statusCode, message, "")

	// Parse Retry-After header if present (for 429 and 503 responses)
	if retryAfter := parseRetryAfter(headers.Get("Retry-After")); retryAfter > 0 {
		return &retryableError{err: apiErr, retryAfter: retryAfter}
	}

	return apiErr
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

// shouldRetry determines if a request should be retried.
func (t *transport) shouldRetry(err error, attempt int) bool {
	if attempt >= t.maxRetries {
		return false
	}

	// Don't retry on context errors
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Retry on rate limit or server errors
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == 429 || apiErr.StatusCode >= 500
	}

	// Retry on temporary network errors
	var netErr interface{ Temporary() bool }
	if errors.As(err, &netErr) && netErr.Temporary() {
		return true
	}

	// Retry on connection reset, timeout, and similar transient errors
	// These are typically wrapped in url.Error
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		// Retry timeouts and temporary errors
		if urlErr.Timeout() || urlErr.Temporary() {
			return true
		}
	}

	return false
}

// backoffDelay calculates the backoff delay for a retry attempt.
func (t *transport) backoffDelay(attempt int) time.Duration {
	// Exponential backoff with jitter
	delay := time.Duration(float64(baseRetryDelay) * math.Pow(2, float64(attempt-1)))
	if delay > maxRetryDelay {
		delay = maxRetryDelay
	}

	// Add jitter (0-25% of delay) using per-transport RNG
	jitter := time.Duration(t.rng.Float64() * 0.25 * float64(delay))
	return delay + jitter
}

// updateRateLimitFromHeaders updates the rate limiter based on response headers.
func (t *transport) updateRateLimitFromHeaders(headers http.Header) {
	if t.rateLimiter == nil {
		return
	}

	// X-Vulners-Ratelimit-Reqlimit header contains the rate limit
	if limitStr := headers.Get("X-Vulners-Ratelimit-Reqlimit"); limitStr != "" {
		if limit, err := strconv.ParseFloat(limitStr, 64); err == nil && limit > 0 {
			t.rateLimiter.UpdateRate(limit)
		}
	}
}

// doGet performs a GET request with query parameters.
func (t *transport) doGet(ctx context.Context, path string, params map[string]string, result any) error {
	if len(params) > 0 {
		values := url.Values{}
		for k, v := range params {
			values.Set(k, v)
		}
		path = path + "?" + values.Encode()
	}
	return t.do(ctx, http.MethodGet, path, nil, result)
}

// doPost performs a POST request with a JSON body.
func (t *transport) doPost(ctx context.Context, path string, body, result any) error {
	return t.do(ctx, http.MethodPost, path, body, result)
}

// doPostMultipart performs a POST request with a multipart/form-data body containing a single file field.
func (t *transport) doPostMultipart(ctx context.Context, path, fieldName, fileName string, r io.Reader, result any) error {
	// Buffer the entire multipart body so retries can re-read it.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile(fieldName, fileName)
	if err != nil {
		return fmt.Errorf("failed to create multipart field: %w", err)
	}
	if _, err := io.Copy(part, r); err != nil {
		return fmt.Errorf("failed to write multipart data: %w", err)
	}
	if err := mw.Close(); err != nil {
		return fmt.Errorf("failed to close multipart writer: %w", err)
	}
	bodyBytes := buf.Bytes()
	contentType := mw.FormDataContentType()

	var attempt int
	for {
		if t.rateLimiter != nil {
			if err := t.rateLimiter.WaitContext(ctx); err != nil {
				return err
			}
		}

		err := t.doOnceRaw(ctx, path, bodyBytes, contentType, result)
		if err == nil {
			return nil
		}

		if !t.shouldRetry(err, attempt) {
			return err
		}

		attempt++

		delay := t.backoffDelay(attempt)
		var retryErr *retryableError
		if errors.As(err, &retryErr) && retryErr.retryAfter > 0 {
			delay = retryErr.retryAfter
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

// doOnceRaw performs a single POST request with a pre-built body and content type.
func (t *transport) doOnceRaw(ctx context.Context, path string, body []byte, contentType string, result any) error {
	reqURL := t.baseURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if t.apiKey != "" {
		req.Header.Set("X-Api-Key", t.apiKey)
	}
	req.Header.Set("User-Agent", t.userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Content-Type", contentType)

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	t.updateRateLimitFromHeaders(resp.Header)

	return t.handleResponseDirect(resp, result)
}

// handleResponseDirect processes the HTTP response by unmarshaling the body
// directly into result, without the apiResponse wrapper. Used for v4 endpoints
// that return {"result": T} instead of {"result": "OK", "data": T}.
func (t *transport) handleResponseDirect(resp *http.Response, result any) error {
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer func() { _ = gzReader.Close() }()
		reader = gzReader
	}

	limitedReader := &io.LimitedReader{R: reader, N: maxResponseSize + 1}
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	if limitedReader.N == 0 {
		return fmt.Errorf("vulners: response body exceeds maximum size of %d bytes", maxResponseSize)
	}

	if resp.StatusCode >= 400 {
		return t.handleErrorResponse(resp.StatusCode, bodyBytes, resp.Header)
	}

	if len(bodyBytes) == 0 || result == nil {
		return nil
	}

	if err := json.Unmarshal(bodyBytes, result); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return nil
}

// doPut performs a PUT request with a JSON body.
func (t *transport) doPut(ctx context.Context, path string, body, result any) error {
	return t.do(ctx, http.MethodPut, path, body, result)
}

// doDelete performs a DELETE request.
func (t *transport) doDelete(ctx context.Context, path string, result any) error {
	return t.do(ctx, http.MethodDelete, path, nil, result)
}
