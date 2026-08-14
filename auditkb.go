package vulners

import (
	"context"
	"fmt"
)

const maxKBAuditItems = 2500

// KBAuditAdvisory is one Windows update the host is missing, carrying the CVEs
// it and the updates it supersedes remediate.
type KBAuditAdvisory struct {
	ID       string `json:"id"`
	Type     string `json:"type,omitempty"`
	Title    string `json:"title,omitempty"`
	Href     string `json:"href,omitempty"`
	Severity string `json:"severity,omitempty"`
	MSFamily string `json:"msfamily,omitempty"`
	// AffectedProducts is a display label, not a matching key: it carries no
	// version and is empty on updates that fix nothing, so fall back to Title.
	AffectedProducts []string `json:"affectedProducts,omitempty"`
	Published        *Time    `json:"published,omitempty"`
	Modified         *Time    `json:"modified,omitempty"`
	// Supersedes answers why installing one update clears a four-figure finding
	// count; without it that number reads as arbitrary.
	Supersedes     []string         `json:"supersedes,omitempty"`
	CVEList        []string         `json:"cvelist,omitempty"`
	Metrics        *AdvisoryMetrics `json:"metrics,omitempty"`
	CVEListMetrics []CVEListMetric  `json:"cvelistMetrics,omitempty"`
}

// KBAuditIssue is the audited operating system and what it is missing.
type KBAuditIssue struct {
	Package string `json:"package"`
	Version string `json:"version,omitempty"`
	// FixedPackage is the update to install: the newest non-preview cumulative
	// among those missing.
	FixedPackage string            `json:"fixedPackage,omitempty"`
	Advisories   []KBAuditAdvisory `json:"advisories,omitempty"`
}

// KBAuditV4Result is the response of /api/v4/audit/kb.
type KBAuditV4Result struct {
	Items         []KBAuditIssue `json:"items"`
	TotalPackages int            `json:"totalPackages"`
}

type kbAuditV4Request struct {
	OSName    string   `json:"osName"`
	KBList    []string `json:"kbList"`
	OSVersion string   `json:"osVersion,omitempty"`
	// This endpoint validates its options strictly, so only values it can
	// answer are sent.
	Fields         []string `json:"fields,omitempty"`
	CVEListMetrics bool     `json:"cvelistMetrics,omitempty"`
}

type kbAuditV4Response struct {
	Result KBAuditV4Result `json:"result"`
}

// KBAuditV4 audits Windows update state against Microsoft KB bulletins.
//
// Unlike the v3 endpoint, which returns every missing CVE in one flat list with
// nothing tying them to the update that fixes them, this groups them under the
// updates to install. A host missing a single cumulative update therefore yields
// one finding with a remediation rather than thousands with none.
//
// osName must match an `affectedProducts` value of the KB bulletins, e.g.
// "Windows Server 2022". Installed updates may be given as "KB5041160",
// "kb5041160" or "5041160".
//
// Only "metrics" and "cvelistMetrics" are accepted in fields; anything else is
// rejected by the endpoint rather than ignored.
func (s *AuditService) KBAuditV4(
	ctx context.Context,
	osName string,
	kbList []string,
	opts ...AuditOption,
) (*KBAuditV4Result, error) {
	if err := validateRequired("osName", osName); err != nil {
		return nil, err
	}
	if len(kbList) == 0 {
		return nil, fmt.Errorf("%w: kbList is required", ErrInvalidInput)
	}
	if len(kbList) > maxKBAuditItems {
		return nil, fmt.Errorf("%w: kbList must contain at most %d items", ErrInvalidInput, maxKBAuditItems)
	}

	cfg := applyAuditOptions(opts)
	req := kbAuditV4Request{
		OSName:         osName,
		KBList:         kbList,
		OSVersion:      cfg.osVersion,
		Fields:         cfg.fields,
		CVEListMetrics: cfg.cveListMetrics,
	}

	var resp kbAuditV4Response
	if err := s.transport.doPost(ctx, "/api/v4/audit/kb", req, &resp); err != nil {
		return nil, err
	}

	return &resp.Result, nil
}
