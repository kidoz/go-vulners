// Package vulners provides a Go client for the Vulners vulnerability database API.
//
// Basic usage:
//
//	client, err := vulners.NewClient("your-api-key")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	results, err := client.Search().SearchBulletins(ctx, "cve-2021-44228")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// The client supports functional options for customization:
//
//	client, err := vulners.NewClient("your-api-key",
//	    vulners.WithTimeout(60 * time.Second),
//	    vulners.WithRetries(5),
//	)
package vulners

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client is the main entry point for the Vulners API.
type Client struct {
	transport *transport

	// Lazy-initialized service clients
	searchOnce       sync.Once
	search           *SearchService
	auditOnce        sync.Once
	audit            *AuditService
	miscOnce         sync.Once
	misc             *MiscService
	archiveOnce      sync.Once
	archive          *ArchiveService
	reportOnce       sync.Once
	report           *ReportService
	webhookOnce      sync.Once
	webhook          *WebhookService
	subscriptionOnce sync.Once
	subscription     *SubscriptionService
	stixOnce         sync.Once
	stix             *StixService
}

// Option is a functional option for configuring the Client.
type Option func(*clientConfig)

// clientConfig holds the configuration for the client.
type clientConfig struct {
	baseURL       string
	timeout       time.Duration
	maxRetries    int
	httpClient    *http.Client
	userAgent     string
	rateLimit     float64
	rateBurst     int
	proxyURL      string
	allowInsecure bool // allow HTTP (for testing only)
}

// NewClient creates a new Vulners API client.
// An API key is required for most operations.
func NewClient(apiKey string, opts ...Option) (*Client, error) {
	if apiKey == "" {
		return nil, ErrAPIKeyRequired
	}

	// Apply default configuration
	cfg := &clientConfig{
		baseURL:    defaultBaseURL,
		timeout:    defaultTimeout,
		maxRetries: defaultMaxRetries,
		userAgent:  defaultUserAgent,
		rateLimit:  defaultRateLimit,
		rateBurst:  defaultBurst,
	}

	// Apply options
	for _, opt := range opts {
		opt(cfg)
	}

	// Validate base URL uses HTTPS (security: prevent API key leakage over HTTP)
	if !cfg.allowInsecure {
		parsedURL, err := url.Parse(cfg.baseURL)
		if err != nil {
			return nil, fmt.Errorf("invalid base URL: %w", err)
		}
		isLocalhost := strings.HasPrefix(parsedURL.Host, "localhost") ||
			strings.HasPrefix(parsedURL.Host, "127.0.0.1") ||
			strings.HasPrefix(parsedURL.Host, "[::1]")
		if parsedURL.Scheme != "https" && !isLocalhost {
			return nil, fmt.Errorf("vulners: base URL must use HTTPS to protect API key (use WithAllowInsecure for testing)")
		}
	}

	// Create HTTP client if not provided
	httpClient := cfg.httpClient
	if httpClient == nil {
		// Clone DefaultTransport to preserve standard defaults (proxy, timeouts, HTTP/2)
		transport := http.DefaultTransport.(*http.Transport).Clone()

		// Configure proxy if specified (overrides system proxy)
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

	// Create rate limiter
	rateLimiter := NewRateLimiter(cfg.rateLimit, cfg.rateBurst)

	// Create transport
	t := newTransport(
		httpClient,
		cfg.baseURL,
		apiKey,
		cfg.userAgent,
		cfg.maxRetries,
		rateLimiter,
	)

	return &Client{transport: t}, nil
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
//	client, err := vulners.NewClient("key", vulners.WithHTTPClient(httpClient))
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

// WithAllowInsecure allows using HTTP instead of HTTPS.
// WARNING: This is insecure and should only be used for local testing.
// Using HTTP will expose your API key to network attackers.
func WithAllowInsecure() Option {
	return func(c *clientConfig) {
		c.allowInsecure = true
	}
}

// WithRateLimit sets the rate limit (requests per second) and burst size.
func WithRateLimit(rate float64, burst int) Option {
	return func(c *clientConfig) {
		c.rateLimit = rate
		c.rateBurst = burst
	}
}

// Search returns the SearchService for searching bulletins.
func (c *Client) Search() *SearchService {
	c.searchOnce.Do(func() {
		c.search = &SearchService{transport: c.transport}
	})
	return c.search
}

// Audit returns the AuditService for vulnerability auditing.
func (c *Client) Audit() *AuditService {
	c.auditOnce.Do(func() {
		c.audit = &AuditService{transport: c.transport}
	})
	return c.audit
}

// Misc returns the MiscService for miscellaneous operations.
func (c *Client) Misc() *MiscService {
	c.miscOnce.Do(func() {
		c.misc = &MiscService{transport: c.transport}
	})
	return c.misc
}

// Archive returns the ArchiveService for fetching collections.
func (c *Client) Archive() *ArchiveService {
	c.archiveOnce.Do(func() {
		c.archive = &ArchiveService{transport: c.transport}
	})
	return c.archive
}

// Report returns the ReportService for vulnerability reports.
func (c *Client) Report() *ReportService {
	c.reportOnce.Do(func() {
		c.report = &ReportService{transport: c.transport}
	})
	return c.report
}

// Webhook returns the WebhookService for webhook management.
func (c *Client) Webhook() *WebhookService {
	c.webhookOnce.Do(func() {
		c.webhook = &WebhookService{transport: c.transport}
	})
	return c.webhook
}

// Subscription returns the SubscriptionService for subscription management.
func (c *Client) Subscription() *SubscriptionService {
	c.subscriptionOnce.Do(func() {
		c.subscription = &SubscriptionService{transport: c.transport}
	})
	return c.subscription
}

// Stix returns the StixService for STIX bundle generation.
func (c *Client) Stix() *StixService {
	c.stixOnce.Do(func() {
		c.stix = &StixService{transport: c.transport}
	})
	return c.stix
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
			return fmt.Errorf("vulners: refusing to follow redirect to different host: %s", req.URL.Host)
		}
		// Block redirects that downgrade from HTTPS to HTTP
		if parsedBase != nil && parsedBase.Scheme == "https" && req.URL.Scheme == "http" {
			return fmt.Errorf("vulners: refusing to follow redirect from HTTPS to HTTP")
		}
		return nil
	}
}
