package vulners

import "encoding/json"

// CVEListMetric is one entry of the per-CVE `cvelistMetrics` array that every
// audit endpoint emits under the same name and the same shape.
//
// The audit endpoints assemble this list in more than one place server-side, but
// the entry itself is a single shared projection, so a client can parse it the
// same way whichever endpoint produced it.
type CVEListMetric struct {
	CVE          string        `json:"cve"`
	Published    *Time         `json:"published,omitempty"`
	CVSS         *CVSS         `json:"cvss,omitempty"`
	EPSS         []Epss        `json:"epss,omitempty"`
	Exploitation *Exploitation `json:"exploitation,omitempty"`
	AIScore      *AIScore      `json:"ai_score,omitempty"`
	SSVC         *SSVC         `json:"ssvc,omitempty"`
}

// SSVC is the CISA stakeholder-specific vulnerability categorization decision
// for a CVE, passed through from the CVE 5.x ADP record.
//
// It grades every CVE, where KEV flags only the rare exploited handful, which
// makes it the practical basis for ordering a list of findings.
type SSVC struct {
	ID        string       `json:"id,omitempty"`
	Role      string       `json:"role,omitempty"`
	Version   string       `json:"version,omitempty"`
	Timestamp string       `json:"timestamp,omitempty"`
	Options   []SSVCOption `json:"options,omitempty"`
}

// SSVCOption is one decision axis. The upstream record is an array of
// single-key objects - {"Exploitation": "active"} - and is preserved as such
// rather than flattened, so the SDK does not invent a second representation of
// somebody else's standard.
type SSVCOption map[string]string

// SSVC decision values that callers commonly branch on. The set is open: an
// unrecognised value must not be treated as absent.
const (
	SSVCExploitationNone   = "none"
	SSVCExploitationPOC    = "poc"
	SSVCExploitationActive = "active"
)

// Exploitation returns the value of the SSVC "Exploitation" axis, or "" when
// the block carries no such axis.
func (s *SSVC) Exploitation() string {
	return s.axis("Exploitation")
}

// Automatable returns the value of the SSVC "Automatable" axis, or "".
func (s *SSVC) Automatable() string {
	return s.axis("Automatable")
}

// TechnicalImpact returns the value of the SSVC "Technical Impact" axis, or "".
func (s *SSVC) TechnicalImpact() string {
	return s.axis("Technical Impact")
}

func (s *SSVC) axis(name string) string {
	if s == nil {
		return ""
	}
	for _, option := range s.Options {
		if v, ok := option[name]; ok {
			return v
		}
	}
	return ""
}

// MaxCVSS returns the highest CVSS base score across the entries, and whether
// any entry carried one at all.
func MaxCVSS(metrics []CVEListMetric) (float64, bool) {
	var best float64
	var found bool
	for _, m := range metrics {
		if m.CVSS == nil {
			continue
		}
		if !found || m.CVSS.Score > best {
			best, found = m.CVSS.Score, true
		}
	}
	return best, found
}

// CVEMetrics decodes the advisory's per-CVE metrics into typed entries.
//
// The raw field predates this type and stays as it is so existing callers keep
// compiling; this accessor is the typed way to read the same data. A malformed
// entry yields an error rather than a partially filled struct.
//
// The receiver is a pointer because the advisory is a heavy struct: iterate the
// advisory slice by index rather than by value, or the copy costs more than the
// decode does.
func (a *AuditApplicableAdvisory) CVEMetrics() ([]CVEListMetric, error) {
	if len(a.CVEListMetrics) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(a.CVEListMetrics)
	if err != nil {
		return nil, err
	}
	var out []CVEListMetric
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AdvisoryMetrics is the advisory-level rollup: the highest severity across the
// advisory's CVEs, maintained server-side rather than recomputed by the client.
type AdvisoryMetrics struct {
	CVSS *CVSS  `json:"cvss,omitempty"`
	EPSS []Epss `json:"epss,omitempty"`
}

// UnmarshalJSON accepts both shapes the API produces for `metrics.epss`.
//
// Normally it is a list of EPSS records. When the EPSS store is slow or
// unavailable the endpoint degrades to serving the bare CVE ids instead of
// failing the request, so a client that only handles records breaks exactly when
// the platform is already having a bad day.
func (m *AdvisoryMetrics) UnmarshalJSON(data []byte) error {
	var raw struct {
		CVSS *CVSS             `json:"cvss,omitempty"`
		EPSS []json.RawMessage `json:"epss,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	m.CVSS = raw.CVSS
	m.EPSS = nil
	for _, entry := range raw.EPSS {
		var record Epss
		if err := json.Unmarshal(entry, &record); err == nil {
			m.EPSS = append(m.EPSS, record)
			continue
		}
		var cve string
		if err := json.Unmarshal(entry, &cve); err != nil {
			return err
		}
		m.EPSS = append(m.EPSS, Epss{Cve: cve})
	}
	return nil
}
