package vulners

import (
	"encoding/json"
	"time"
)

// DefaultFields is the default set of fields returned in search results.
const DefaultFields = "id,title,description,type,bulletinFamily,cvss,published,modified,href,sourceHref,sourceData,cvelist"

// Bulletin represents a vulnerability bulletin from the Vulners database.
type Bulletin struct {
	ID               string             `json:"id,omitempty"`
	Type             string             `json:"type,omitempty"`
	BulletinFamily   string             `json:"bulletinFamily,omitempty"`
	Title            string             `json:"title,omitempty"`
	Description      string             `json:"description,omitempty"`
	Published        *Time              `json:"published,omitempty"`
	Modified         *Time              `json:"modified,omitempty"`
	CVSS             *CVSS              `json:"cvss,omitempty"`
	CVSS2            *CVSS              `json:"cvss2,omitempty"`
	CVSS3            *CVSS              `json:"cvss3,omitempty"`
	CVEList          []string           `json:"cvelist,omitempty"`
	Href             string             `json:"href,omitempty"`
	SourceHref       string             `json:"sourceHref,omitempty"`
	SourceData       json.RawMessage    `json:"sourceData,omitempty"`
	Reporter         string             `json:"reporter,omitempty"`
	References       []string           `json:"references,omitempty"`
	Enchantments     json.RawMessage    `json:"enchantments,omitempty"`
	Epss             []Epss             `json:"epss,omitempty"`
	AffectedSoftware []AffectedSoftware `json:"affectedSoftware,omitempty"`

	// Additional fields that may be present
	VulnStatus    string         `json:"vulnStatus,omitempty"`
	AI            *AIScore       `json:"ai,omitempty"`
	History       []HistoryEntry `json:"history,omitempty"`
	ObjectVersion string         `json:"objectVersion,omitempty"`
	LastSeenAt    *Time          `json:"lastseen,omitempty"`
}

// UnmarshalJSON implements json.Unmarshaler for Bulletin.
// It handles underscore-prefixed fields used in search results.
func (b *Bulletin) UnmarshalJSON(data []byte) error {
	// Use an alias to avoid infinite recursion
	type bulletinAlias Bulletin
	aux := &struct {
		*bulletinAlias
		// Alternative underscore-prefixed fields used in search results
		AltID             string `json:"_id,omitempty"`
		AltType           string `json:"_type,omitempty"`
		AltTitle          string `json:"_title,omitempty"`
		AltBulletinFamily string `json:"_bulletinFamily,omitempty"`
		// Nested source object (Elasticsearch-style responses)
		Source *bulletinAlias `json:"_source,omitempty"`
		// Flat source fields (alternative naming)
		FlatSource json.RawMessage `json:"flatDescription,omitempty"`
	}{
		bulletinAlias: (*bulletinAlias)(b),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// If there's a _source object, use its fields
	if aux.Source != nil {
		*b = Bulletin(*aux.Source)
	}

	// Use underscore-prefixed fields as fallbacks
	if b.ID == "" && aux.AltID != "" {
		b.ID = aux.AltID
	}
	if b.Type == "" && aux.AltType != "" {
		b.Type = aux.AltType
	}
	if b.Title == "" && aux.AltTitle != "" {
		b.Title = aux.AltTitle
	}
	if b.BulletinFamily == "" && aux.AltBulletinFamily != "" {
		b.BulletinFamily = aux.AltBulletinFamily
	}

	return nil
}

// CVSS represents CVSS scoring information.
type CVSS struct {
	Score    float64 `json:"score,omitempty"`
	Vector   string  `json:"vector,omitempty"`
	Version  string  `json:"version,omitempty"`
	Severity string  `json:"severity,omitempty"`

	// CVSS v3 specific fields
	AttackVector          string `json:"attackVector,omitempty"`
	AttackComplexity      string `json:"attackComplexity,omitempty"`
	PrivilegesRequired    string `json:"privilegesRequired,omitempty"`
	UserInteraction       string `json:"userInteraction,omitempty"`
	Scope                 string `json:"scope,omitempty"`
	ConfidentialityImpact string `json:"confidentialityImpact,omitempty"`
	IntegrityImpact       string `json:"integrityImpact,omitempty"`
	AvailabilityImpact    string `json:"availabilityImpact,omitempty"`
}

// Epss represents EPSS (Exploit Prediction Scoring System) data.
type Epss struct {
	Cve        string  `json:"cve,omitempty"`
	Epss       float64 `json:"epss,omitempty"`
	Percentile float64 `json:"percentile,omitempty"`
}

// AffectedSoftware represents software affected by a vulnerability.
type AffectedSoftware struct {
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	CPE      string `json:"cpe,omitempty"`
	Operator string `json:"operator,omitempty"`
}

// AIScore represents AI-generated vulnerability scoring.
type AIScore struct {
	Score       float64 `json:"score,omitempty"`
	Severity    string  `json:"severity,omitempty"`
	Explanation string  `json:"explanation,omitempty"`
}

// HistoryEntry represents a change history entry.
type HistoryEntry struct {
	Date        *Time           `json:"date,omitempty"`
	Description string          `json:"description,omitempty"`
	Changes     json.RawMessage `json:"changes,omitempty"`
}

// SearchResult represents a search response from the API.
type SearchResult struct {
	Total     int        `json:"total,omitempty"`
	Bulletins []Bulletin `json:"search,omitempty"`
	Took      int        `json:"took,omitempty"`
}

// AuditResult represents an audit response from the API.
type AuditResult struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	Reasons         []AuditReason   `json:"reasons,omitempty"`
	CVEList         []string        `json:"cvelist,omitempty"`
	CVSSScore       float64         `json:"cvss,omitempty"`
	CumulativeFix   string          `json:"cumulativeFix,omitempty"`
}

// Vulnerability represents a vulnerability found during audit.
type Vulnerability struct {
	Package    string   `json:"package,omitempty"`
	Operator   string   `json:"operator,omitempty"`
	Version    string   `json:"providedVersion,omitempty"`
	BulletinID string   `json:"bulletinID,omitempty"`
	CVEList    []string `json:"cvelist,omitempty"`
	CVSS       *CVSS    `json:"cvss,omitempty"`
	Fix        string   `json:"fix,omitempty"`
}

// AuditReason represents a reason for a vulnerability match.
type AuditReason struct {
	Package         string   `json:"package,omitempty"`
	ProvidedVersion string   `json:"providedVersion,omitempty"`
	BulletinVersion string   `json:"bulletinVersion,omitempty"`
	BulletinID      string   `json:"bulletinID,omitempty"`
	Operator        string   `json:"operator,omitempty"`
	CVEList         []string `json:"cvelist,omitempty"`
}

// AuditItem represents a software item for auditing.
type AuditItem struct {
	Software string `json:"software"`
	Version  string `json:"version"`
	Type     string `json:"type,omitempty"`
}

// WinAuditItem represents a Windows software item for auditing.
type WinAuditItem struct {
	Software string `json:"software"`
	Version  string `json:"version"`
}

// LinuxAuditRequest represents a Linux audit request.
type LinuxAuditRequest struct {
	OS       string   `json:"os"`
	Version  string   `json:"version"`
	Packages []string `json:"package"`
}

// SBOMAuditResult represents the response from the SBOM audit endpoint.
type SBOMAuditResult struct {
	Packages []SBOMPackageResult `json:"result"`
}

// SBOMPackageResult represents audit findings for a single package in an SBOM.
type SBOMPackageResult struct {
	Package              string         `json:"package"`
	Version              string         `json:"version"`
	FixedVersion         *string        `json:"fixedVersion"`
	ApplicableAdvisories []SBOMAdvisory `json:"applicableAdvisories"`
}

// SBOMAdvisory represents a security advisory applicable to an SBOM package.
type SBOMAdvisory struct {
	ID               string          `json:"id"`
	Type             string          `json:"type"`
	Match            string          `json:"match"`
	Title            string          `json:"title"`
	Description      string          `json:"description"`
	AIDescription    string          `json:"aiDescription,omitempty"`
	Published        *Time           `json:"published"`
	EPSS             json.RawMessage `json:"epss,omitempty"`
	AIScore          json.RawMessage `json:"aiScore,omitempty"`
	Metrics          json.RawMessage `json:"metrics,omitempty"`
	Exploitation     json.RawMessage `json:"exploitation,omitempty"`
	Enchantments     json.RawMessage `json:"enchantments,omitempty"`
	WebApplicability json.RawMessage `json:"webApplicability,omitempty"`
	References       []string        `json:"references,omitempty"`
	Exploits         json.RawMessage `json:"exploits,omitempty"`
}

// CPEResult represents a CPE search result.
type CPEResult struct {
	CPE     string `json:"cpe,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
}

// Webhook represents a webhook configuration.
type Webhook struct {
	ID       string `json:"id,omitempty"`
	Query    string `json:"query,omitempty"`
	Active   bool   `json:"active,omitempty"`
	Created  *Time  `json:"created,omitempty"`
	Modified *Time  `json:"modified,omitempty"`
}

// WebhookData represents data from a webhook.
type WebhookData struct {
	ID       string     `json:"id,omitempty"`
	Data     []Bulletin `json:"data,omitempty"`
	NewCount int        `json:"new_count,omitempty"`
}

// Subscription represents a v4 subscription.
type Subscription struct {
	ID       string          `json:"id,omitempty"`
	Name     string          `json:"name,omitempty"`
	Type     string          `json:"type,omitempty"`
	Active   bool            `json:"active,omitempty"`
	Query    string          `json:"query,omitempty"`
	Config   json.RawMessage `json:"config,omitempty"`
	Created  *Time           `json:"created,omitempty"`
	Modified *Time           `json:"modified,omitempty"`
}

// SubscriptionRequest represents a request to create/update a subscription.
type SubscriptionRequest struct {
	Name   string          `json:"name,omitempty"`
	Type   string          `json:"type,omitempty"`
	Active bool            `json:"active,omitempty"`
	Query  string          `json:"query,omitempty"`
	Config json.RawMessage `json:"config,omitempty"`
}

// Time is a custom time type that handles various time formats from the API.
type Time struct {
	time.Time
}

// UnmarshalJSON implements json.Unmarshaler for Time.
func (t *Time) UnmarshalJSON(data []byte) error {
	// Handle null
	if string(data) == "null" {
		return nil
	}

	// Remove quotes
	s := string(data)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}

	// Try various formats
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02",
		"2006-01-02 15:04:05",
	}

	var err error
	for _, format := range formats {
		t.Time, err = time.Parse(format, s)
		if err == nil {
			return nil
		}
	}

	// Try parsing as Unix timestamp (milliseconds)
	var ms int64
	if err := json.Unmarshal(data, &ms); err == nil {
		t.Time = time.UnixMilli(ms)
		return nil
	}

	return err
}

// MarshalJSON implements json.Marshaler for Time.
func (t Time) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(t.Format(time.RFC3339))
}

// apiResponse is the common wrapper for API responses.
type apiResponse struct {
	Result string          `json:"result"`
	Data   json.RawMessage `json:"data,omitempty"`
	Error  string          `json:"error,omitempty"`
}
