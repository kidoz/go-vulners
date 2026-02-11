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
	CVSS3            *CVSS3             `json:"cvss3,omitempty"`
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
	Assigned      *Time          `json:"assigned,omitempty"`
	VulnStatus    string         `json:"vulnStatus,omitempty"`
	AI            *AIScore       `json:"ai,omitempty"`
	CVSS4         *CVSS          `json:"cvss4,omitempty"`
	History       []HistoryEntry `json:"history,omitempty"`
	ObjectVersion string         `json:"objectVersion,omitempty"`
	LastSeenAt    *Time          `json:"lastseen,omitempty"`

	// Search-result metadata (present only in search responses)
	VHref           string `json:"vhref,omitempty"`
	ViewCount       int    `json:"viewCount,omitempty"`
	SourceAvailable bool   `json:"sourceAvailable,omitempty"`
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
		Source json.RawMessage `json:"_source,omitempty"`
	}{
		bulletinAlias: (*bulletinAlias)(b),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// If there's a _source object, merge its fields into b.
	// Using json.Unmarshal (not replace) preserves any top-level fields
	// that are absent from _source.
	if len(aux.Source) > 0 {
		if err := json.Unmarshal(aux.Source, (*bulletinAlias)(b)); err != nil {
			return err
		}
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
	Source   string  `json:"source,omitempty"`

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

// CVSS3 wraps CVSS to handle NVD-style nested CVSS v3 responses.
//
// The API returns cvss3 as {"cvssV3": {"baseScore":9.8, "baseSeverity":"CRITICAL", "vectorString":"CVSS:3.1/...", ...}}.
// This type transparently flattens that into the embedded CVSS fields.
type CVSS3 struct {
	CVSS
}

// UnmarshalJSON implements json.Unmarshaler for CVSS3.
// It handles both the NVD wrapper format {"cvssV3": {...}} and flat CVSS format.
func (c *CVSS3) UnmarshalJSON(data []byte) error {
	// Try NVD wrapper format first: {"cvssV3": {"baseScore": ..., "baseSeverity": ..., "vectorString": ...}}
	var wrapper struct {
		CvssV3 *nvdCVSS3 `json:"cvssV3"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && wrapper.CvssV3 != nil {
		c.Score = wrapper.CvssV3.BaseScore
		c.Severity = wrapper.CvssV3.BaseSeverity
		c.Vector = wrapper.CvssV3.VectorString
		c.Version = wrapper.CvssV3.Version
		c.AttackVector = wrapper.CvssV3.AttackVector
		c.AttackComplexity = wrapper.CvssV3.AttackComplexity
		c.PrivilegesRequired = wrapper.CvssV3.PrivilegesRequired
		c.UserInteraction = wrapper.CvssV3.UserInteraction
		c.Scope = wrapper.CvssV3.Scope
		c.ConfidentialityImpact = wrapper.CvssV3.ConfidentialityImpact
		c.IntegrityImpact = wrapper.CvssV3.IntegrityImpact
		c.AvailabilityImpact = wrapper.CvssV3.AvailabilityImpact
		c.Source = wrapper.CvssV3.Source
		return nil
	}

	// Fall back to flat CVSS format
	return json.Unmarshal(data, &c.CVSS)
}

// nvdCVSS3 represents the NVD CVSS v3 field naming convention.
type nvdCVSS3 struct {
	Version               string  `json:"version,omitempty"`
	BaseScore             float64 `json:"baseScore,omitempty"`
	BaseSeverity          string  `json:"baseSeverity,omitempty"`
	VectorString          string  `json:"vectorString,omitempty"`
	AttackVector          string  `json:"attackVector,omitempty"`
	AttackComplexity      string  `json:"attackComplexity,omitempty"`
	PrivilegesRequired    string  `json:"privilegesRequired,omitempty"`
	UserInteraction       string  `json:"userInteraction,omitempty"`
	Scope                 string  `json:"scope,omitempty"`
	ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact       string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
	Source                string  `json:"source,omitempty"`
}

// Epss represents EPSS (Exploit Prediction Scoring System) data.
type Epss struct {
	Cve        string  `json:"cve,omitempty"`
	Epss       float64 `json:"epss,omitempty"`
	Percentile float64 `json:"percentile,omitempty"`
	Date       string  `json:"date,omitempty"`
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
//
// Fields match the SBOM audit endpoint response format: {"value": 10.0, "uncertainty": 0.1}.
type AIScore struct {
	Value       float64 `json:"value,omitempty"`
	Uncertainty float64 `json:"uncertainty,omitempty"`
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

// SBOMMetrics contains CVSS scoring information for an SBOM advisory.
type SBOMMetrics struct {
	CVSS *CVSS    `json:"cvss,omitempty"`
	EPSS []string `json:"epss,omitempty"`
}

// ExploitationSource identifies a source that reported wild exploitation.
type ExploitationSource struct {
	Type   string   `json:"type,omitempty"`
	IDList []string `json:"idList,omitempty"`
}

// Exploitation describes whether a vulnerability is exploited in the wild.
type Exploitation struct {
	WildExploited        bool                 `json:"wildExploited"`
	WildExploitedSources []ExploitationSource `json:"wildExploitedSources,omitempty"`
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
	CVEList          []string        `json:"cvelist,omitempty"`
	EPSS             []Epss          `json:"epss,omitempty"`
	AIScore          *AIScore        `json:"aiScore,omitempty"`
	Metrics          *SBOMMetrics    `json:"metrics,omitempty"`
	Exploitation     *Exploitation   `json:"exploitation,omitempty"`
	Enchantments     json.RawMessage `json:"enchantments,omitempty"`
	WebApplicability json.RawMessage `json:"webApplicability,omitempty"`
	References       []string        `json:"references,omitempty"`
	Exploits         json.RawMessage `json:"exploits,omitempty"`
}

// EnchantmentsScore represents the AI score from the enchantments field.
type EnchantmentsScore struct {
	Value       float64 `json:"value,omitempty"`
	Uncertainty float64 `json:"uncertanity,omitempty"` //nolint:misspell // API typo preserved
	Vector      string  `json:"vector,omitempty"`
}

// GetEnchantmentsScore extracts the AI score from the Enchantments raw JSON.
// Returns nil if enchantments is empty or does not contain a score.
func (b *Bulletin) GetEnchantmentsScore() *EnchantmentsScore {
	return parseEnchantmentsScore(b.Enchantments)
}

// GetEnchantmentsScore extracts the AI score from the Enchantments raw JSON.
// Returns nil if enchantments is empty or does not contain a score.
func (a *SBOMAdvisory) GetEnchantmentsScore() *EnchantmentsScore {
	return parseEnchantmentsScore(a.Enchantments)
}

func parseEnchantmentsScore(raw json.RawMessage) *EnchantmentsScore {
	if len(raw) == 0 {
		return nil
	}
	var enc struct {
		Score *EnchantmentsScore `json:"score"`
	}
	if err := json.Unmarshal(raw, &enc); err != nil {
		return nil
	}
	return enc.Score
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
	// Handle null — reset to zero value
	if string(data) == "null" {
		t.Time = time.Time{}
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
