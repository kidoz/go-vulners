package vscanner

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// ResultService provides methods for accessing VScanner scan results.
type ResultService struct {
	client *Client
}

// Result represents a VScanner scan result. Screens maps a port (as a string)
// to per-port screenshot metadata; use Client.GetScreenshot with the "screen"
// URI to fetch the image bytes.
type Result struct {
	ID        string                  `json:"_id,omitempty"`
	ProjectID string                  `json:"project_id,omitempty"`
	Screens   map[string]ResultScreen `json:"screens,omitempty"`
}

// ResultScreen holds per-port screenshot metadata.
type ResultScreen struct {
	Screen string `json:"screen,omitempty"`
}

// ResultOption is a functional option for filtering scan results.
type ResultOption func(*resultConfig)

type resultConfig struct {
	search  string
	inPorts []string
	exPorts []string
	minCVSS *float64
	maxCVSS *float64
	sort    string
	sortDir string
	offset  int
	limit   int
}

// WithResultSearch filters results by ip, network, name, or vuln_id.
func WithResultSearch(query string) ResultOption {
	return func(c *resultConfig) { c.search = query }
}

// WithResultIncludePorts restricts results to the given ports.
func WithResultIncludePorts(ports ...string) ResultOption {
	return func(c *resultConfig) { c.inPorts = ports }
}

// WithResultExcludePorts excludes the given ports from results.
func WithResultExcludePorts(ports ...string) ResultOption {
	return func(c *resultConfig) { c.exPorts = ports }
}

// WithResultCVSSRange filters results by CVSS score range. Use a negative
// bound to leave it unset.
func WithResultCVSSRange(minCVSS, maxCVSS float64) ResultOption {
	return func(c *resultConfig) {
		if minCVSS >= 0 {
			c.minCVSS = &minCVSS
		}
		if maxCVSS >= 0 {
			c.maxCVSS = &maxCVSS
		}
	}
}

// WithResultSort sets the sort field and direction. field must be one of
// ip, name, last_seen, first_seen, resolved, min_cvss, or max_cvss.
func WithResultSort(field string, ascending bool) ResultOption {
	return func(c *resultConfig) {
		c.sort = field
		if ascending {
			c.sortDir = "asc"
		} else {
			c.sortDir = "desc"
		}
	}
}

// WithResultLimit sets the maximum number of results to return (max 1000).
func WithResultLimit(limit int) ResultOption {
	return func(c *resultConfig) { c.limit = limit }
}

// WithResultOffset sets the pagination offset.
func WithResultOffset(offset int) ResultOption {
	return func(c *resultConfig) { c.offset = offset }
}

func (c *resultConfig) values() url.Values {
	values := url.Values{}
	if c.search != "" {
		values.Set("search", c.search)
	}
	for _, p := range c.inPorts {
		values.Add("in_port", p)
	}
	for _, p := range c.exPorts {
		values.Add("ex_port", p)
	}
	if c.minCVSS != nil {
		values.Set("min_cvss", strconv.FormatFloat(*c.minCVSS, 'f', -1, 64))
	}
	if c.maxCVSS != nil {
		values.Set("max_cvss", strconv.FormatFloat(*c.maxCVSS, 'f', -1, 64))
	}
	if c.sort != "" {
		values.Set("sort", c.sort)
	}
	if c.sortDir != "" {
		values.Set("sort_dir", c.sortDir)
	}
	if c.offset > 0 {
		values.Set("offset", strconv.Itoa(c.offset))
	}
	if c.limit > 0 {
		values.Set("limit", strconv.Itoa(c.limit))
	}
	return values
}

func resultsPath(projectID string) string {
	return projectsBasePath + url.PathEscape(projectID) + "/results"
}

// List returns scan results for a project.
func (s *ResultService) List(ctx context.Context, projectID string, opts ...ResultOption) ([]Result, error) {
	cfg := &resultConfig{limit: 50}
	for _, opt := range opts {
		opt(cfg)
	}

	path := resultsPath(projectID)
	if values := cfg.values(); len(values) > 0 {
		path += "?" + values.Encode()
	}

	var results []Result
	if err := s.client.doGet(ctx, path, nil, &results); err != nil {
		return nil, err
	}
	return results, nil
}

// Delete removes a scan result.
func (s *ResultService) Delete(ctx context.Context, projectID, resultID string) error {
	if resultID == "" {
		return fmt.Errorf("vscanner: result ID is required")
	}
	path := resultsPath(projectID) + "/" + url.PathEscape(resultID)
	return s.client.doDelete(ctx, path, nil)
}
