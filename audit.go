package vulners

import (
	"context"
	"fmt"
	"io"
	"sort"
)

// AuditService provides methods for vulnerability auditing.
type AuditService struct {
	transport *transport
}

// AuditOption is a functional option for audit operations.
type AuditOption func(*auditConfig)

type auditConfig struct {
	includeCandidates *bool
	includeUnofficial bool
	includeAnyVersion bool
	cveListMetrics    bool
	osArch            string
	match             string
	fields            []string
	config            []string
	catalog           string
}

// WithIncludeCandidates controls whether candidate advisories are included.
func WithIncludeCandidates(v bool) AuditOption {
	return func(c *auditConfig) {
		c.includeCandidates = &v
	}
}

// WithAuditMatch sets the CPE matching mode to "partial" or "full".
func WithAuditMatch(match string) AuditOption {
	return func(c *auditConfig) {
		c.match = match
	}
}

// WithAuditFields sets the bulletin fields returned by software and host audits.
func WithAuditFields(fields ...string) AuditOption {
	return func(c *auditConfig) {
		c.fields = fields
	}
}

// WithAuditConfig sets the named CPE matching configurations.
func WithAuditConfig(config ...string) AuditOption {
	return func(c *auditConfig) {
		c.config = config
	}
}

// WithAuditCatalog sets the CPE catalog to "official" or "extended".
func WithAuditCatalog(catalog string) AuditOption {
	return func(c *auditConfig) {
		c.catalog = catalog
	}
}

// WithIncludeUnofficial controls whether unofficial package matches are included.
func WithIncludeUnofficial(v bool) AuditOption {
	return func(c *auditConfig) {
		c.includeUnofficial = v
	}
}

// WithIncludeAnyVersion controls whether advisories matching any package version are included.
func WithIncludeAnyVersion(v bool) AuditOption {
	return func(c *auditConfig) {
		c.includeAnyVersion = v
	}
}

// WithCVEListMetrics controls whether CVE-list metrics are included for eligible licenses.
func WithCVEListMetrics(v bool) AuditOption {
	return func(c *auditConfig) {
		c.cveListMetrics = v
	}
}

// WithOSArch sets the default package architecture for a modern Linux audit.
func WithOSArch(arch string) AuditOption {
	return func(c *auditConfig) {
		c.osArch = arch
	}
}

// softwareAuditRequest represents a software audit request.
type softwareAuditRequest struct {
	Software []AuditItem `json:"software"`
	Match    string      `json:"match,omitempty"`
	Fields   []string    `json:"fields,omitempty"`
	Config   []string    `json:"config,omitempty"`
	Catalog  string      `json:"catalog,omitempty"`
}

// hostAuditRequest represents a host audit request (v4 API).
type hostAuditRequest struct {
	Software        []AuditItem `json:"software"`
	OperatingSystem AuditItem   `json:"operatingSystem"`
	Match           string      `json:"match,omitempty"`
	Fields          []string    `json:"fields,omitempty"`
	Config          []string    `json:"config,omitempty"`
	Catalog         string      `json:"catalog,omitempty"`
}

// linuxAuditRequest represents a Linux audit request.
type linuxAuditRequest struct {
	OS                string   `json:"os"`
	Version           string   `json:"version"`
	Packages          []string `json:"package"`
	IncludeCandidates *bool    `json:"include_candidates,omitempty"`
}

// linuxAuditV4Request represents a modern Linux audit request.
type linuxAuditV4Request struct {
	OSName            string   `json:"osName"`
	OSVersion         string   `json:"osVersion"`
	OSArch            string   `json:"osArch,omitempty"`
	Packages          []string `json:"packages"`
	IncludeUnofficial bool     `json:"includeUnofficial,omitempty"`
	IncludeCandidates bool     `json:"includeCandidates,omitempty"`
	IncludeAnyVersion bool     `json:"includeAnyVersion,omitempty"`
	CVEListMetrics    bool     `json:"cvelistMetrics,omitempty"`
}

// libraryAuditRequest represents a PURL library audit request.
type libraryAuditRequest struct {
	Packages          []string `json:"packages"`
	IncludeUnofficial bool     `json:"includeUnofficial,omitempty"`
	IncludeCandidates bool     `json:"includeCandidates,omitempty"`
	IncludeAnyVersion bool     `json:"includeAnyVersion,omitempty"`
	CVEListMetrics    bool     `json:"cvelistMetrics,omitempty"`
}

type cveAuditRequest struct {
	CVE interface{} `json:"cve"`
}

type packageAuditV4Response struct {
	Result PackageAuditResult `json:"result"`
}

type cveAuditV4Response struct {
	Result CVEAuditIssue `json:"result"`
}

type cveBatchAuditV4Response struct {
	Result []CVEAuditIssue `json:"result"`
}

// kbAuditRequest represents a KB audit request.
type kbAuditRequest struct {
	OS      string   `json:"os"`
	KBs     []string `json:"kbList"`
	Details bool     `json:"details,omitempty"`
}

// winAuditRequest represents a Windows audit request.
type winAuditRequest struct {
	OS        string         `json:"os"`
	OSVersion string         `json:"os_version"`
	KBs       []string       `json:"kb_list"`
	Software  []WinAuditItem `json:"software"`
	APIKey    string         `json:"apiKey"`
}

// auditV4Response wraps []SoftwareAuditItem for the v4 API format.
// The v4 /api/v4/audit/software and /api/v4/audit/host endpoints return
// {"result": [...]} instead of the v3 {"result": "OK", "data": {...}} format.
type auditV4Response struct {
	Result []SoftwareAuditItem `json:"result"`
}

// supportedOSResponse represents the getSupportedOS API response.
type supportedOSResponse struct {
	SupportedOS map[string]string `json:"supportedOS"`
}

type sbomAuditV4Response struct {
	Result SBOMAuditResult `json:"result"`
}

// auditResponse represents the audit API response.
type auditResponse struct {
	// Packages is map[packageName]map[bulletinID][]AuditVuln per OpenAPI spec
	Packages map[string]map[string][]AuditVuln `json:"packages,omitempty"`
	// Vulnerabilities is a list of bulletin IDs (strings), not full objects
	Vulnerabilities []string      `json:"vulnerabilities,omitempty"`
	Reasons         []AuditReason `json:"reasons,omitempty"`
	CVEList         []string      `json:"cvelist,omitempty"`
	// Details carries per-CVE objects (id/cvss/cvelist) returned by
	// /api/v3/audit/kb so callers get CVSS without a second lookup.
	Details []AuditVuln `json:"details,omitempty"`
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
func (s *AuditService) Software(ctx context.Context, software []AuditItem, opts ...AuditOption) (*SoftwareAuditResult, error) {
	if len(software) == 0 {
		return nil, fmt.Errorf("%w: software is required", ErrInvalidInput)
	}
	if len(software) > 500 {
		return nil, fmt.Errorf("%w: software must contain at most 500 items", ErrInvalidInput)
	}

	cfg := applyAuditOptions(opts)
	req := softwareAuditRequest{
		Software: software,
		Match:    cfg.match,
		Fields:   cfg.fields,
		Config:   cfg.config,
		Catalog:  cfg.catalog,
	}

	var resp auditV4Response
	if err := s.transport.doPost(ctx, "/api/v4/audit/software/", req, &resp); err != nil {
		return nil, err
	}

	return &SoftwareAuditResult{Items: resp.Result}, nil
}

// Host performs a host audit using the v4 API.
// It checks the OS and installed packages for vulnerabilities.
func (s *AuditService) Host(ctx context.Context, os, osVersion string, packages []AuditItem, opts ...AuditOption) (*SoftwareAuditResult, error) {
	if err := validateRequired("os", os); err != nil {
		return nil, err
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("%w: software is required", ErrInvalidInput)
	}
	if len(packages) > 200 {
		return nil, fmt.Errorf("%w: software must contain at most 200 items", ErrInvalidInput)
	}

	cfg := applyAuditOptions(opts)
	req := hostAuditRequest{
		Software: packages,
		OperatingSystem: AuditItem{
			Part:    "o",
			Product: os,
			Version: osVersion,
		},
		Match:   cfg.match,
		Fields:  cfg.fields,
		Config:  cfg.config,
		Catalog: cfg.catalog,
	}

	var resp auditV4Response
	if err := s.transport.doPost(ctx, "/api/v4/audit/host/", req, &resp); err != nil {
		return nil, err
	}

	return &SoftwareAuditResult{Items: resp.Result}, nil
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

// LinuxAuditV4 performs a Linux package audit using the modern v4 endpoint.
// Package entries may use RPM, DEB, or APK formats.
func (s *AuditService) LinuxAuditV4(ctx context.Context, osName, osVersion string, packages []string, opts ...AuditOption) (*PackageAuditResult, error) {
	if err := validateRequired("osName", osName); err != nil {
		return nil, err
	}
	if err := validateRequired("osVersion", osVersion); err != nil {
		return nil, err
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("%w: packages are required", ErrInvalidInput)
	}
	if len(packages) > 2500 {
		return nil, fmt.Errorf("%w: packages must contain at most 2500 items", ErrInvalidInput)
	}

	cfg := applyAuditOptions(opts)
	req := linuxAuditV4Request{
		OSName:            osName,
		OSVersion:         osVersion,
		OSArch:            cfg.osArch,
		Packages:          packages,
		IncludeUnofficial: cfg.includeUnofficial,
		IncludeCandidates: auditBool(cfg.includeCandidates),
		IncludeAnyVersion: cfg.includeAnyVersion,
		CVEListMetrics:    cfg.cveListMetrics,
	}

	var resp packageAuditV4Response
	if err := s.transport.doPost(ctx, "/api/v4/audit/linux", req, &resp); err != nil {
		return nil, err
	}

	return &resp.Result, nil
}

// LibraryAudit audits packages identified by Package URLs (PURLs).
func (s *AuditService) LibraryAudit(ctx context.Context, packages []string, opts ...AuditOption) (*PackageAuditResult, error) {
	if len(packages) == 0 {
		return nil, fmt.Errorf("%w: packages are required", ErrInvalidInput)
	}
	if len(packages) > 2500 {
		return nil, fmt.Errorf("%w: packages must contain at most 2500 items", ErrInvalidInput)
	}

	cfg := applyAuditOptions(opts)
	req := libraryAuditRequest{
		Packages:          packages,
		IncludeUnofficial: cfg.includeUnofficial,
		IncludeCandidates: auditBool(cfg.includeCandidates),
		IncludeAnyVersion: cfg.includeAnyVersion,
		CVEListMetrics:    cfg.cveListMetrics,
	}

	var resp packageAuditV4Response
	if err := s.transport.doPost(ctx, "/api/v4/audit/library", req, &resp); err != nil {
		return nil, err
	}

	return &resp.Result, nil
}

// CVEAudit returns package and CPE definitions affected by one CVE or CAN identifier.
func (s *AuditService) CVEAudit(ctx context.Context, cve string) (*CVEAuditIssue, error) {
	if err := validateRequired("cve", cve); err != nil {
		return nil, err
	}

	var resp cveAuditV4Response
	if err := s.transport.doPost(ctx, "/api/v4/audit/cve", cveAuditRequest{CVE: cve}, &resp); err != nil {
		return nil, err
	}

	return &resp.Result, nil
}

// CVEBatchAudit returns affected definitions for up to 500 CVE or CAN identifiers.
func (s *AuditService) CVEBatchAudit(ctx context.Context, cves []string) ([]CVEAuditIssue, error) {
	if len(cves) == 0 {
		return nil, fmt.Errorf("%w: cves are required", ErrInvalidInput)
	}
	if len(cves) > 500 {
		return nil, fmt.Errorf("%w: cves must contain at most 500 items", ErrInvalidInput)
	}

	var resp cveBatchAuditV4Response
	if err := s.transport.doPost(ctx, "/api/v4/audit/cves", cveAuditRequest{CVE: cves}, &resp); err != nil {
		return nil, err
	}

	return resp.Result, nil
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
		// Request per-CVE CVSS details so the result carries scored vulnerabilities.
		Details: true,
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
		APIKey:    s.transport.apiKey,
	}

	var resp auditResponse
	if err := s.transport.doPost(ctx, "/api/v3/audit/winaudit/", req, &resp); err != nil {
		return nil, err
	}

	return s.convertResponse(&resp), nil
}

// GetSupportedOS returns the list of operating system identifiers that are valid
// inputs for Linux-package audit requests.
func (s *AuditService) GetSupportedOS(ctx context.Context) ([]string, error) {
	var resp supportedOSResponse
	if err := s.transport.doGet(ctx, "/api/v3/audit/getSupportedOS", nil, &resp); err != nil {
		return nil, err
	}

	osList := make([]string, 0, len(resp.SupportedOS))
	for osName := range resp.SupportedOS {
		osList = append(osList, osName)
	}
	sort.Strings(osList)
	return osList, nil
}

// SBOMAudit performs an SBOM-based audit by uploading an SBOM file.
// The reader r should provide the SBOM content in SPDX or CycloneDX JSON format
// (e.g., an os.File or bytes.Buffer).
func (s *AuditService) SBOMAudit(ctx context.Context, r io.Reader, opts ...AuditOption) (*SBOMAuditResult, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: SBOM reader is required", ErrInvalidInput)
	}

	var resp sbomAuditV4Response
	if err := s.transport.doPostMultipart(ctx, "/api/v4/audit/sbom", "file", "sbom", r, &resp); err != nil {
		return nil, err
	}

	return &resp.Result, nil
}

func applyAuditOptions(opts []AuditOption) auditConfig {
	var cfg auditConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

func auditBool(value *bool) bool {
	return value != nil && *value
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

	// KB audit (/api/v3/audit/kb) returns per-CVE objects with CVSS scores under
	// "details"; convert them to vulnerabilities so callers get scores.
	for i := range resp.Details {
		d := &resp.Details[i]
		result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
			Package:    d.Package,
			BulletinID: d.BulletinID,
			CVEList:    d.CVEList,
			CVSS:       d.CVSS,
			Fix:        d.Fix,
			Version:    d.ProvidedVersion,
			Operator:   d.Operator,
		})
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
