package vulners

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	ReportType string                 `json:"reporttype"`
	Filter     map[string]interface{} `json:"filter"`
	Sort       string                 `json:"sort"`
	Size       int                    `json:"size"`
	Skip       int                    `json:"skip"`
}

type reportResponse struct {
	Report json.RawMessage
}

func (r *reportResponse) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		r.Report = append(r.Report[:0], data...)
		return nil
	}
	var envelope struct {
		Report json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	if len(envelope.Report) > 0 {
		r.Report = envelope.Report
	} else {
		r.Report = append(r.Report[:0], data...)
	}
	return nil
}

// VulnsSummaryReport gets a summary of vulnerabilities.
func (s *ReportService) VulnsSummaryReport(ctx context.Context, opts ...ReportOption) (*VulnsSummary, error) {
	cfg := &reportConfig{
		limit: 100,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	var resp VulnsSummary
	if err := s.doReport(ctx, "vulnssummary", cfg, &resp); err != nil {
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

	var resp []VulnItem
	if err := s.doReport(ctx, "vulnslist", cfg, &resp); err != nil {
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

	var resp IPSummary
	if err := s.doReport(ctx, "ipsummary", cfg, &resp); err != nil {
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

	var resp []ScanItem
	if err := s.doReport(ctx, "scanlist", cfg, &resp); err != nil {
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

	var resp []HostVuln
	if err := s.doReport(ctx, "hostvulns", cfg, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *ReportService) doReport(ctx context.Context, reportType string, cfg *reportConfig, result interface{}) error {
	sortField := cfg.sort
	if sortField != "" && cfg.order == "desc" {
		sortField = "-" + sortField
	}
	limit := cfg.limit
	if limit == 0 {
		limit = 30
	}
	req := reportRequest{
		ReportType: reportType,
		Filter:     cfg.filter,
		Sort:       sortField,
		Size:       limit,
		Skip:       cfg.offset,
	}

	var resp reportResponse
	if err := s.transport.doPost(ctx, "/api/v3/reports/vulnsreport", req, &resp); err != nil {
		return err
	}
	if err := json.Unmarshal(resp.Report, result); err != nil {
		if reportType == "vulnssummary" || reportType == "ipsummary" {
			var rows []json.RawMessage
			if arrayErr := json.Unmarshal(resp.Report, &rows); arrayErr == nil {
				if len(rows) == 0 {
					return nil
				}
				if rowErr := json.Unmarshal(rows[0], result); rowErr == nil {
					return nil
				}
			}
		}
		return fmt.Errorf("failed to decode %s report: %w", reportType, err)
	}
	return nil
}
