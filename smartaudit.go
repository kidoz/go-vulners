package vulners

import (
	"context"
	"fmt"
	"unicode/utf8"
)

const (
	maxSmartAuditItems      = 500
	maxSmartAuditItemLength = 512
)

// SmartAuditResult represents the response from the Smart Audit endpoint.
type SmartAuditResult struct {
	Items []SmartAuditItem `json:"items,omitempty"`
}

// SmartAuditItem represents the match and vulnerabilities for one submitted software string.
type SmartAuditItem struct {
	Input           string                    `json:"input"`
	CPE             string                    `json:"cpe"`
	PURLs           []string                  `json:"purls"`
	Confidence      float64                   `json:"confidence"`
	Vulnerabilities []SmartAuditVulnerability `json:"vulnerabilities"`
}

// SmartAuditVulnerability represents a vulnerability matched by Smart Audit.
type SmartAuditVulnerability struct {
	ID               string             `json:"id"`
	Reasons          []SmartAuditReason `json:"reasons"`
	Title            string             `json:"title,omitempty"`
	ShortDescription string             `json:"short_description,omitempty"`
	Type             string             `json:"type,omitempty"`
	Href             string             `json:"href,omitempty"`
	Published        *Time              `json:"published,omitempty"`
	Modified         *Time              `json:"modified,omitempty"`
	AIScore          *AIScore           `json:"ai_score,omitempty"`
}

// SmartAuditReason describes a CPE rule that caused a vulnerability to match.
type SmartAuditReason struct {
	Config   string                  `json:"config"`
	Criteria [][]SmartAuditCriterion `json:"criterias"` //nolint:misspell // API field name preserved.
}

// SmartAuditCriterion describes one condition in a Smart Audit match rule.
type SmartAuditCriterion struct {
	Criteria              string `json:"criteria"`
	Vulnerable            bool   `json:"vulnerable"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

type smartAuditRequest struct {
	Software []string `json:"software"`
	Catalog  string   `json:"catalog,omitempty"`
}

type smartAuditResponse struct {
	Result []SmartAuditItem `json:"result"`
}

// SmartAudit resolves raw software descriptions to CPEs and audits them for vulnerabilities.
func (s *AuditService) SmartAudit(ctx context.Context, software []string, opts ...AuditOption) (*SmartAuditResult, error) {
	if len(software) == 0 {
		return nil, fmt.Errorf("%w: software is required", ErrInvalidInput)
	}
	if len(software) > maxSmartAuditItems {
		return nil, fmt.Errorf("%w: software must contain at most %d items", ErrInvalidInput, maxSmartAuditItems)
	}
	for i, item := range software {
		length := utf8.RuneCountInString(item)
		if length == 0 || length > maxSmartAuditItemLength {
			return nil, fmt.Errorf(
				"%w: software item %d must contain between 1 and %d characters",
				ErrInvalidInput,
				i,
				maxSmartAuditItemLength,
			)
		}
	}

	cfg := applyAuditOptions(opts)
	if cfg.catalog != "" && cfg.catalog != "official" && cfg.catalog != "extended" {
		return nil, fmt.Errorf("%w: catalog must be official or extended", ErrInvalidInput)
	}

	req := smartAuditRequest{
		Software: software,
		Catalog:  cfg.catalog,
	}

	var resp smartAuditResponse
	if err := s.transport.doPost(ctx, "/api/v4/audit/smart", req, &resp); err != nil {
		return nil, err
	}

	return &SmartAuditResult{Items: resp.Result}, nil
}
