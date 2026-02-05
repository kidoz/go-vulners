package vulners

import (
	"context"
)

// ReportService provides methods for vulnerability reporting.
type ReportService struct {
	transport *transport
}

// ReportOption is a functional option for report operations.
type ReportOption func(*reportConfig)

type reportConfig struct {
	filter map[string]interface{}
	sort   string
	order  string
	limit  int
	offset int
}

// WithFilter sets a filter for the report.
func WithFilter(filter map[string]interface{}) ReportOption {
	return func(c *reportConfig) {
		c.filter = filter
	}
}

// WithReportSort sets the sort field and order for the report.
func WithReportSort(field string, ascending bool) ReportOption {
	return func(c *reportConfig) {
		c.sort = field
		if ascending {
			c.order = "asc"
		} else {
			c.order = "desc"
		}
	}
}

// WithReportLimit sets the limit for the report.
func WithReportLimit(limit int) ReportOption {
	return func(c *reportConfig) {
		c.limit = limit
	}
}

// WithReportOffset sets the offset for the report.
func WithReportOffset(offset int) ReportOption {
	return func(c *reportConfig) {
		c.offset = offset
	}
}

// VulnsSummary represents a vulnerability summary.
type VulnsSummary struct {
	Total      int            `json:"total,omitempty"`
	Critical   int            `json:"critical,omitempty"`
	High       int            `json:"high,omitempty"`
	Medium     int            `json:"medium,omitempty"`
	Low        int            `json:"low,omitempty"`
	Info       int            `json:"info,omitempty"`
	Severities map[string]int `json:"severities,omitempty"`
}

// VulnItem represents an individual vulnerability in a list.
type VulnItem struct {
	ID        string   `json:"id,omitempty"`
	Title     string   `json:"title,omitempty"`
	Severity  string   `json:"severity,omitempty"`
	CVSS      float64  `json:"cvss,omitempty"`
	CVEList   []string `json:"cvelist,omitempty"`
	Published *Time    `json:"published,omitempty"`
	HostCount int      `json:"hostCount,omitempty"`
}

// IPSummary represents an IP summary report.
type IPSummary struct {
	Total     int `json:"total,omitempty"`
	WithVulns int `json:"withVulns,omitempty"`
	Critical  int `json:"critical,omitempty"`
	High      int `json:"high,omitempty"`
	Medium    int `json:"medium,omitempty"`
	Low       int `json:"low,omitempty"`
}

// ScanItem represents a scan in the scan list.
type ScanItem struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Status     string `json:"status,omitempty"`
	StartedAt  *Time  `json:"startedAt,omitempty"`
	FinishedAt *Time  `json:"finishedAt,omitempty"`
	HostCount  int    `json:"hostCount,omitempty"`
	VulnCount  int    `json:"vulnCount,omitempty"`
}

// HostVuln represents a vulnerability found on a host.
type HostVuln struct {
	ID       string   `json:"id,omitempty"`
	Host     string   `json:"host,omitempty"`
	Port     int      `json:"port,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	VulnID   string   `json:"vulnId,omitempty"`
	Title    string   `json:"title,omitempty"`
	Severity string   `json:"severity,omitempty"`
	CVSS     float64  `json:"cvss,omitempty"`
	CVEList  []string `json:"cvelist,omitempty"`
}

// reportRequest represents a generic report request.
type reportRequest struct {
	Filter map[string]interface{} `json:"filter,omitempty"`
	Sort   string                 `json:"sort,omitempty"`
	Order  string                 `json:"order,omitempty"`
	Limit  int                    `json:"limit,omitempty"`
	Offset int                    `json:"offset,omitempty"`
}

// VulnsSummaryReport gets a summary of vulnerabilities.
func (s *ReportService) VulnsSummaryReport(ctx context.Context, opts ...ReportOption) (*VulnsSummary, error) {
	cfg := &reportConfig{
		limit: 100,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	req := reportRequest{
		Filter: cfg.filter,
	}

	var resp VulnsSummary
	if err := s.transport.doPost(ctx, "/api/v3/report/vulns/summary/", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// VulnsList gets a list of vulnerabilities.
func (s *ReportService) VulnsList(ctx context.Context, opts ...ReportOption) ([]VulnItem, error) {
	cfg := &reportConfig{
		limit: 100,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	req := reportRequest{
		Filter: cfg.filter,
		Sort:   cfg.sort,
		Order:  cfg.order,
		Limit:  cfg.limit,
		Offset: cfg.offset,
	}

	var resp []VulnItem
	if err := s.transport.doPost(ctx, "/api/v3/report/vulns/list/", req, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// IPSummaryReport gets a summary of IP addresses.
func (s *ReportService) IPSummaryReport(ctx context.Context, opts ...ReportOption) (*IPSummary, error) {
	cfg := &reportConfig{}

	for _, opt := range opts {
		opt(cfg)
	}

	req := reportRequest{
		Filter: cfg.filter,
	}

	var resp IPSummary
	if err := s.transport.doPost(ctx, "/api/v3/report/ip/summary/", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// ScanList gets a list of scans.
func (s *ReportService) ScanList(ctx context.Context, opts ...ReportOption) ([]ScanItem, error) {
	cfg := &reportConfig{
		limit: 100,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	req := reportRequest{
		Filter: cfg.filter,
		Sort:   cfg.sort,
		Order:  cfg.order,
		Limit:  cfg.limit,
		Offset: cfg.offset,
	}

	var resp []ScanItem
	if err := s.transport.doPost(ctx, "/api/v3/report/scan/list/", req, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// HostVulns gets vulnerabilities for hosts.
func (s *ReportService) HostVulns(ctx context.Context, opts ...ReportOption) ([]HostVuln, error) {
	cfg := &reportConfig{
		limit: 100,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	req := reportRequest{
		Filter: cfg.filter,
		Sort:   cfg.sort,
		Order:  cfg.order,
		Limit:  cfg.limit,
		Offset: cfg.offset,
	}

	var resp []HostVuln
	if err := s.transport.doPost(ctx, "/api/v3/report/host/vulns/", req, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}
