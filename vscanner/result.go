package vscanner

import (
	"context"
	"fmt"
)

// ResultService provides methods for managing VScanner results.
type ResultService struct {
	client *Client
}

// Result represents a VScanner scan result.
type Result struct {
	ID         string      `json:"id,omitempty"`
	ProjectID  string      `json:"projectId,omitempty"`
	TaskID     string      `json:"taskId,omitempty"`
	TaskName   string      `json:"taskName,omitempty"`
	Status     string      `json:"status,omitempty"`
	StartedAt  *Time       `json:"startedAt,omitempty"`
	FinishedAt *Time       `json:"finishedAt,omitempty"`
	HostCount  int         `json:"hostCount,omitempty"`
	VulnCount  int         `json:"vulnCount,omitempty"`
	Statistics *Statistics `json:"statistics,omitempty"`
}

// Statistics represents scan result statistics.
type Statistics struct {
	TotalHosts   int            `json:"totalHosts,omitempty"`
	ScannedHosts int            `json:"scannedHosts,omitempty"`
	TotalVulns   int            `json:"totalVulns,omitempty"`
	BySeverity   map[string]int `json:"bySeverity,omitempty"`
	ByType       map[string]int `json:"byType,omitempty"`
	TopVulns     []VulnSummary  `json:"topVulns,omitempty"`
	TopHosts     []HostSummary  `json:"topHosts,omitempty"`
}

// VulnSummary represents a vulnerability summary.
type VulnSummary struct {
	ID        string   `json:"id,omitempty"`
	Title     string   `json:"title,omitempty"`
	Severity  string   `json:"severity,omitempty"`
	CVSS      float64  `json:"cvss,omitempty"`
	CVEList   []string `json:"cvelist,omitempty"`
	HostCount int      `json:"hostCount,omitempty"`
}

// HostSummary represents a host summary.
type HostSummary struct {
	Host      string `json:"host,omitempty"`
	IP        string `json:"ip,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	OS        string `json:"os,omitempty"`
	VulnCount int    `json:"vulnCount,omitempty"`
	Critical  int    `json:"critical,omitempty"`
	High      int    `json:"high,omitempty"`
	Medium    int    `json:"medium,omitempty"`
	Low       int    `json:"low,omitempty"`
}

// HostDetail represents detailed host information.
type HostDetail struct {
	Host            string         `json:"host,omitempty"`
	IP              string         `json:"ip,omitempty"`
	Hostname        string         `json:"hostname,omitempty"`
	OS              string         `json:"os,omitempty"`
	Ports           []PortInfo     `json:"ports,omitempty"`
	Vulnerabilities []HostVulnInfo `json:"vulnerabilities,omitempty"`
}

// PortInfo represents port information.
type PortInfo struct {
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	State    string `json:"state,omitempty"`
	Service  string `json:"service,omitempty"`
	Version  string `json:"version,omitempty"`
}

// HostVulnInfo represents vulnerability information for a host.
type HostVulnInfo struct {
	ID       string   `json:"id,omitempty"`
	Title    string   `json:"title,omitempty"`
	Severity string   `json:"severity,omitempty"`
	CVSS     float64  `json:"cvss,omitempty"`
	CVEList  []string `json:"cvelist,omitempty"`
	Port     int      `json:"port,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
}

// resultListResponse represents the result list response.
type resultListResponse struct {
	Results []Result `json:"results"`
	Total   int      `json:"total,omitempty"`
}

// List returns all results for a project.
func (s *ResultService) List(ctx context.Context, projectID string, opts ...ListOption) ([]Result, error) {
	cfg := &listConfig{
		limit: 100,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	params := map[string]string{
		"projectId": projectID,
	}
	if cfg.limit > 0 {
		params["limit"] = fmt.Sprintf("%d", cfg.limit)
	}
	if cfg.offset > 0 {
		params["offset"] = fmt.Sprintf("%d", cfg.offset)
	}
	if cfg.sort != "" {
		params["sort"] = cfg.sort
	}
	if cfg.order != "" {
		params["order"] = cfg.order
	}

	var resp resultListResponse
	if err := s.client.doGet(ctx, "/api/v3/vscanner/results", params, &resp); err != nil {
		return nil, err
	}

	return resp.Results, nil
}

// Get retrieves a result by ID.
func (s *ResultService) Get(ctx context.Context, projectID, resultID string) (*Result, error) {
	params := map[string]string{
		"projectId": projectID,
		"resultId":  resultID,
	}

	var result Result
	if err := s.client.doGet(ctx, "/api/v3/vscanner/result", params, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetStatistics retrieves statistics for a result.
func (s *ResultService) GetStatistics(ctx context.Context, projectID, resultID string) (*Statistics, error) {
	params := map[string]string{
		"projectId": projectID,
		"resultId":  resultID,
	}

	var stats Statistics
	if err := s.client.doGet(ctx, "/api/v3/vscanner/result/statistics", params, &stats); err != nil {
		return nil, err
	}

	return &stats, nil
}

// GetHosts retrieves hosts from a result.
func (s *ResultService) GetHosts(ctx context.Context, projectID, resultID string, opts ...ListOption) ([]HostSummary, error) {
	cfg := &listConfig{
		limit: 100,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	params := map[string]string{
		"projectId": projectID,
		"resultId":  resultID,
	}
	if cfg.limit > 0 {
		params["limit"] = fmt.Sprintf("%d", cfg.limit)
	}
	if cfg.offset > 0 {
		params["offset"] = fmt.Sprintf("%d", cfg.offset)
	}

	var hosts []HostSummary
	if err := s.client.doGet(ctx, "/api/v3/vscanner/result/hosts", params, &hosts); err != nil {
		return nil, err
	}

	return hosts, nil
}

// GetHostDetail retrieves detailed information for a specific host.
func (s *ResultService) GetHostDetail(ctx context.Context, projectID, resultID, host string) (*HostDetail, error) {
	params := map[string]string{
		"projectId": projectID,
		"resultId":  resultID,
		"host":      host,
	}

	var detail HostDetail
	if err := s.client.doGet(ctx, "/api/v3/vscanner/result/host", params, &detail); err != nil {
		return nil, err
	}

	return &detail, nil
}

// GetVulnerabilities retrieves vulnerabilities from a result.
func (s *ResultService) GetVulnerabilities(ctx context.Context, projectID, resultID string, opts ...ListOption) ([]VulnSummary, error) {
	cfg := &listConfig{
		limit: 100,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	params := map[string]string{
		"projectId": projectID,
		"resultId":  resultID,
	}
	if cfg.limit > 0 {
		params["limit"] = fmt.Sprintf("%d", cfg.limit)
	}
	if cfg.offset > 0 {
		params["offset"] = fmt.Sprintf("%d", cfg.offset)
	}

	var vulns []VulnSummary
	if err := s.client.doGet(ctx, "/api/v3/vscanner/result/vulnerabilities", params, &vulns); err != nil {
		return nil, err
	}

	return vulns, nil
}

// Delete removes a result.
func (s *ResultService) Delete(ctx context.Context, projectID, resultID string) error {
	req := map[string]string{
		"projectId": projectID,
		"resultId":  resultID,
	}

	return s.client.doPost(ctx, "/api/v3/vscanner/result/delete", req, nil)
}

// Export exports a result in the specified format.
// Supported formats: pdf, csv, json, xml
func (s *ResultService) Export(ctx context.Context, projectID, resultID, format string) ([]byte, error) {
	params := map[string]string{
		"projectId": projectID,
		"resultId":  resultID,
		"format":    format,
	}

	return s.client.doGetRaw(ctx, "/api/v3/vscanner/result/export", params)
}
