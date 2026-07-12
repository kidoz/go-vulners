package vscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

const projectsBasePath = "/api/v3/proxy/vscanner/v2/projects/"

// ProjectService provides methods for managing VScanner projects.
type ProjectService struct {
	client *Client
}

// Notification represents project notification settings.
//
// Period must be one of "disabled", "asap", "hourly", or "daily".
type Notification struct {
	Period string   `json:"period"`
	Email  []string `json:"email"`
	Slack  []string `json:"slack"`
}

// NewNotification builds a Notification object. period must be one of
// "disabled", "asap", "hourly", or "daily". Nil email/slack slices are
// normalized to empty slices, as the API expects.
func NewNotification(period string, emails, slackWebhooks []string) *Notification {
	if emails == nil {
		emails = []string{}
	}
	if slackWebhooks == nil {
		slackWebhooks = []string{}
	}
	return &Notification{Period: period, Email: emails, Slack: slackWebhooks}
}

// DisabledNotification returns a notification object with the "disabled"
// period and empty delivery methods.
func DisabledNotification() *Notification {
	return &Notification{Period: "disabled", Email: []string{}, Slack: []string{}}
}

// Project represents a VScanner project.
type Project struct {
	ID             string        `json:"_id,omitempty"`
	Name           string        `json:"name,omitempty"`
	LicenseID      string        `json:"license_id,omitempty"`
	Notification   *Notification `json:"notification,omitempty"`
	ResultExpireIn *int          `json:"result_expire_in,omitempty"`
}

// ProjectRequest represents a request to create or update a project.
type ProjectRequest struct {
	Name         string        `json:"name"`
	LicenseID    string        `json:"license_id"`
	Notification *Notification `json:"notification"`
	// ResultExpireIn sets result retention in days. A nil value means results
	// never expire.
	ResultExpireIn *int `json:"result_expire_in,omitempty"`
}

// ListOption is a functional option for paginated list operations.
type ListOption func(*listConfig)

type listConfig struct {
	offset int
	limit  int
}

// WithListLimit sets the maximum number of items to return (max 1000).
func WithListLimit(limit int) ListOption {
	return func(c *listConfig) {
		c.limit = limit
	}
}

// WithListOffset sets the pagination offset.
func WithListOffset(offset int) ListOption {
	return func(c *listConfig) {
		c.offset = offset
	}
}

func newListConfig(opts ...ListOption) *listConfig {
	cfg := &listConfig{limit: 50}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

func (c *listConfig) params() map[string]string {
	params := map[string]string{}
	if c.offset > 0 {
		params["offset"] = fmt.Sprintf("%d", c.offset)
	}
	if c.limit > 0 {
		params["limit"] = fmt.Sprintf("%d", c.limit)
	}
	return params
}

// List returns existing projects.
func (s *ProjectService) List(ctx context.Context, opts ...ListOption) ([]Project, error) {
	cfg := newListConfig(opts...)

	var projects []Project
	if err := s.client.doGet(ctx, projectsBasePath, cfg.params(), &projects); err != nil {
		return nil, err
	}
	return projects, nil
}

// Create creates a new project.
func (s *ProjectService) Create(ctx context.Context, req *ProjectRequest) (*Project, error) {
	if req == nil {
		return nil, fmt.Errorf("vscanner: project request is required")
	}

	var project Project
	if err := s.client.doPost(ctx, projectsBasePath, req, &project); err != nil {
		return nil, err
	}
	return &project, nil
}

// Update updates an existing project.
func (s *ProjectService) Update(ctx context.Context, projectID string, req *ProjectRequest) (*Project, error) {
	if req == nil {
		return nil, fmt.Errorf("vscanner: project request is required")
	}

	var project Project
	path := projectsBasePath + url.PathEscape(projectID)
	if err := s.client.doPut(ctx, path, req, &project); err != nil {
		return nil, err
	}
	return &project, nil
}

// Delete removes an existing project.
func (s *ProjectService) Delete(ctx context.Context, projectID string) error {
	path := projectsBasePath + url.PathEscape(projectID)
	return s.client.doDelete(ctx, path, nil)
}

// Statistic aggregation names accepted by GetStatistics.
const (
	StatTotalHosts          = "total_hosts"
	StatVulnerableHosts     = "vulnerable_hosts"
	StatUniqueCVE           = "unique_cve"
	StatMinMaxCVSS          = "min_max_cvss"
	StatVulnerabilitiesRank = "vulnerabilities_rank"
	StatVulnerableHostsRank = "vulnerable_hosts_rank"
)

// GetStatistics returns aggregated project statistics. Pass one or more of the
// Stat* aggregation names. The returned map is keyed by aggregation name with
// aggregation-specific values.
func (s *ProjectService) GetStatistics(ctx context.Context, projectID string, stats ...string) (map[string]json.RawMessage, error) {
	if len(stats) == 0 {
		return nil, fmt.Errorf("vscanner: at least one stat aggregation is required")
	}

	values := url.Values{}
	for _, stat := range stats {
		values.Add("stat", stat)
	}
	path := projectsBasePath + url.PathEscape(projectID) + "/statistic?" + values.Encode()

	var result map[string]json.RawMessage
	if err := s.client.doGet(ctx, path, nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}
