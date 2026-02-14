package vulners

import (
	"context"
	"fmt"
	"io"
)

// AuditService provides methods for vulnerability auditing.
type AuditService struct {
	transport *transport
}

// AuditOption is a functional option for audit operations.
type AuditOption func(*auditConfig)

type auditConfig struct {
	includeCandidates *bool
}

// WithIncludeCandidates controls whether advisories still awaiting vendor
// evaluation are included in the results. The API default is true (include
// everything). Pass false to drop "needs evaluation" items.
func WithIncludeCandidates(v bool) AuditOption {
	return func(c *auditConfig) {
		c.includeCandidates = &v
	}
}

// softwareAuditRequest represents a software audit request.
type softwareAuditRequest struct {
	Software []AuditItem `json:"software"`
	Version  int         `json:"version,omitempty"`
}

// hostAuditRequest represents a host audit request (v4 API).
type hostAuditRequest struct {
	OS        string      `json:"os"`
	OSVersion string      `json:"osVersion,omitempty"`
	Packages  []AuditItem `json:"packages"`
}

// linuxAuditRequest represents a Linux audit request.
type linuxAuditRequest struct {
	OS                string   `json:"os"`
	Version           string   `json:"version"`
	Packages          []string `json:"package"`
	IncludeCandidates *bool    `json:"include_candidates,omitempty"`
}

// kbAuditRequest represents a KB audit request.
type kbAuditRequest struct {
	OS  string   `json:"os"`
	KBs []string `json:"kbList"`
}

// winAuditRequest represents a Windows audit request.
type winAuditRequest struct {
	OS        string         `json:"os"`
	OSVersion string         `json:"osVersion,omitempty"`
	KBs       []string       `json:"kbList,omitempty"`
	Software  []WinAuditItem `json:"software,omitempty"`
}

// auditResponse represents the audit API response.
type auditResponse struct {
	// Packages is map[packageName]map[bulletinID][]AuditVuln per OpenAPI spec
	Packages map[string]map[string][]AuditVuln `json:"packages,omitempty"`
	// Vulnerabilities is a list of bulletin IDs (strings), not full objects
	Vulnerabilities []string      `json:"vulnerabilities,omitempty"`
	Reasons         []AuditReason `json:"reasons,omitempty"`
	CVEList         []string      `json:"cvelist,omitempty"`
	// CVSS is returned as an object, not a simple float
	CVSS          *CVSS  `json:"cvss,omitempty"`
	CumulativeFix string `json:"cumulativeFix,omitempty"`
	ID            string `json:"id,omitempty"`
}

// AuditVuln represents a vulnerability found for a package.
type AuditVuln struct {
	Package         string   `json:"package,omitempty"`
	ProvidedVersion string   `json:"providedVersion,omitempty"`
	BulletinVersion string   `json:"bulletinVersion,omitempty"`
	ProvidedPackage string   `json:"providedPackage,omitempty"`
	BulletinPackage string   `json:"bulletinPackage,omitempty"`
	Operator        string   `json:"operator,omitempty"`
	BulletinID      string   `json:"id,omitempty"`
	CVEList         []string `json:"cvelist,omitempty"`
	Fix             string   `json:"fix,omitempty"`
	CVSS            *CVSS    `json:"cvss,omitempty"`
}

// Software performs a software audit using the v4 API.
// It checks the provided software items for known vulnerabilities.
func (s *AuditService) Software(ctx context.Context, software []AuditItem, opts ...AuditOption) (*AuditResult, error) {
	req := softwareAuditRequest{
		Software: software,
		Version:  4,
	}

	var resp auditResponse
	if err := s.transport.doPost(ctx, "/api/v4/audit/software/", req, &resp); err != nil {
		return nil, err
	}

	return s.convertResponse(&resp), nil
}

// Host performs a host audit using the v4 API.
// It checks the OS and installed packages for vulnerabilities.
func (s *AuditService) Host(ctx context.Context, os, osVersion string, packages []AuditItem, opts ...AuditOption) (*AuditResult, error) {
	if err := validateRequired("os", os); err != nil {
		return nil, err
	}

	req := hostAuditRequest{
		OS:        os,
		OSVersion: osVersion,
		Packages:  packages,
	}

	var resp auditResponse
	if err := s.transport.doPost(ctx, "/api/v4/audit/host/", req, &resp); err != nil {
		return nil, err
	}

	return s.convertResponse(&resp), nil
}

// LinuxAudit performs a Linux-specific audit.
// It checks packages installed on a Linux system for vulnerabilities.
func (s *AuditService) LinuxAudit(ctx context.Context, osName, osVersion string, packages []string, opts ...AuditOption) (*AuditResult, error) {
	if err := validateRequired("osName", osName); err != nil {
		return nil, err
	}

	var cfg auditConfig
	for _, o := range opts {
		o(&cfg)
	}

	req := linuxAuditRequest{
		OS:                osName,
		Version:           osVersion,
		Packages:          packages,
		IncludeCandidates: cfg.includeCandidates,
	}

	var resp auditResponse
	if err := s.transport.doPost(ctx, "/api/v3/audit/audit/", req, &resp); err != nil {
		return nil, err
	}

	return s.convertResponse(&resp), nil
}

// KBAudit performs a Windows KB audit.
// It checks installed Windows KB updates for vulnerabilities.
func (s *AuditService) KBAudit(ctx context.Context, os string, kbList []string, opts ...AuditOption) (*AuditResult, error) {
	if err := validateRequired("os", os); err != nil {
		return nil, err
	}

	req := kbAuditRequest{
		OS:  os,
		KBs: kbList,
	}

	var resp auditResponse
	if err := s.transport.doPost(ctx, "/api/v3/audit/kb/", req, &resp); err != nil {
		return nil, err
	}

	return s.convertResponse(&resp), nil
}

// WinAudit performs a comprehensive Windows audit.
// It checks both KB updates and installed software for vulnerabilities.
func (s *AuditService) WinAudit(ctx context.Context, os, osVersion string, kbList []string, software []WinAuditItem, opts ...AuditOption) (*AuditResult, error) {
	if err := validateRequired("os", os); err != nil {
		return nil, err
	}

	req := winAuditRequest{
		OS:        os,
		OSVersion: osVersion,
		KBs:       kbList,
		Software:  software,
	}

	var resp auditResponse
	if err := s.transport.doPost(ctx, "/api/v3/audit/winaudit/", req, &resp); err != nil {
		return nil, err
	}

	return s.convertResponse(&resp), nil
}

// SBOMAudit performs an SBOM-based audit by uploading an SBOM file.
// The reader r should provide the SBOM content in SPDX or CycloneDX JSON format
// (e.g., an os.File or bytes.Buffer).
func (s *AuditService) SBOMAudit(ctx context.Context, r io.Reader, opts ...AuditOption) (*SBOMAuditResult, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: SBOM reader is required", ErrInvalidInput)
	}

	var resp SBOMAuditResult
	if err := s.transport.doPostMultipart(ctx, "/api/v4/audit/sbom", "file", "sbom", r, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// convertResponse converts the internal audit response to the public AuditResult.
func (s *AuditService) convertResponse(resp *auditResponse) *AuditResult {
	result := &AuditResult{
		Reasons:       resp.Reasons,
		CVEList:       resp.CVEList,
		CumulativeFix: resp.CumulativeFix,
		ID:            resp.ID,
	}

	// Extract CVSS score from the CVSS object
	if resp.CVSS != nil {
		result.CVSSScore = resp.CVSS.Score
	}

	// Convert package-based response to vulnerabilities list
	// Structure is map[packageName]map[bulletinID][]AuditVuln
	if len(resp.Packages) > 0 {
		for pkg, bulletins := range resp.Packages {
			for bulletinID, vulns := range bulletins {
				for i := range vulns {
					v := &vulns[i]
					result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
						Package:    pkg,
						BulletinID: bulletinID,
						CVEList:    v.CVEList,
						CVSS:       v.CVSS,
						Fix:        v.Fix,
						Version:    v.ProvidedVersion,
						Operator:   v.Operator,
					})
				}
			}
		}
	}

	// If vulnerabilities list from response contains bulletin IDs, convert them
	if len(resp.Vulnerabilities) > 0 && len(result.Vulnerabilities) == 0 {
		for _, bulletinID := range resp.Vulnerabilities {
			result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
				BulletinID: bulletinID,
			})
		}
	}

	return result
}
