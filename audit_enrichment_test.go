package vulners

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// Smart Audit could previously report only ai_score, which cannot express KEV
// and tops out below the high band. The enrichment has to be asked for, and the
// answer has to survive decoding.
func TestSmartAudit_RequestsAndDecodesEnrichment(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var request smartAuditRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if len(request.Fields) != 2 || request.Fields[0] != "metrics" {
			t.Fatalf("fields not sent: %v", request.Fields)
		}
		if !request.CVEListMetrics {
			t.Fatal("cvelistMetrics not sent")
		}
		_, _ = w.Write([]byte(`{"result":[{
			"input":"Google Chrome 149.0.7827.89",
			"cpe":"cpe:2.3:a:google:chrome:149.0.7827.89:*:*:*:*:*:*:*",
			"purls":[],"confidence":0.93,
			"fixedVersion":"151.0.7922.138",
			"vulnerabilities":[{
				"id":"GCSA-1","reasons":[],
				"metrics":{"cvss":{"score":9.6,"severity":"CRITICAL"}},
				"exploitation":{"wildExploited":true,
					"wildExploitedSources":[{"type":"cisa_kev"}]},
				"cvelist":["CVE-2026-11645"],
				"cvelistMetrics":[{
					"cve":"CVE-2026-11645",
					"cvss":{"score":9.6},
					"exploitation":{"wildExploited":true},
					"ssvc":{"id":"CVE-2026-11645","role":"CISA Coordinator","version":"2.0.3",
						"options":[{"Exploitation":"active"},{"Automatable":"no"},
						           {"Technical Impact":"total"}]}
				}]
			}]
		}]}`))
	})

	result, err := client.Audit().SmartAudit(
		context.Background(),
		[]string{"Google Chrome 149.0.7827.89"},
		WithAuditFields("metrics", "cvelistMetrics"),
		WithCVEListMetrics(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	item := result.Items[0]
	if item.FixedVersion != "151.0.7922.138" {
		t.Errorf("FixedVersion = %q", item.FixedVersion)
	}
	v := item.Vulnerabilities[0]
	if v.Metrics == nil || v.Metrics.CVSS == nil || v.Metrics.CVSS.Score != 9.6 {
		t.Fatalf("advisory metrics lost: %+v", v.Metrics)
	}
	if v.Exploitation == nil || !v.Exploitation.WildExploited {
		t.Fatalf("KEV flag lost: %+v", v.Exploitation)
	}
	if len(v.CVEListMetrics) != 1 {
		t.Fatalf("per-CVE metrics lost: %+v", v.CVEListMetrics)
	}
	ssvc := v.CVEListMetrics[0].SSVC
	if ssvc.Exploitation() != SSVCExploitationActive {
		t.Errorf("SSVC Exploitation = %q", ssvc.Exploitation())
	}
	if ssvc.Automatable() != "no" || ssvc.TechnicalImpact() != "total" {
		t.Errorf("SSVC axes = %q / %q", ssvc.Automatable(), ssvc.TechnicalImpact())
	}
}

// A nil block must answer like an absent axis rather than panicking: SSVC is
// omitted, not null-filled, on CVEs that have no decision.
func TestSSVC_NilIsSafe(t *testing.T) {
	var ssvc *SSVC
	if ssvc.Exploitation() != "" || ssvc.Automatable() != "" || ssvc.TechnicalImpact() != "" {
		t.Error("nil SSVC should read as empty")
	}
}

func TestSSVC_UnknownAxisIsEmpty(t *testing.T) {
	ssvc := &SSVC{Options: []SSVCOption{{"Automatable": "yes"}}}
	if ssvc.Exploitation() != "" {
		t.Errorf("missing axis should be empty, got %q", ssvc.Exploitation())
	}
}

func TestMaxCVSS(t *testing.T) {
	metrics := []CVEListMetric{
		{CVE: "CVE-1", CVSS: &CVSS{Score: 7.5}},
		{CVE: "CVE-2"},
		{CVE: "CVE-3", CVSS: &CVSS{Score: 9.6}},
	}
	if score, ok := MaxCVSS(metrics); !ok || score != 9.6 {
		t.Errorf("MaxCVSS = %v, %v", score, ok)
	}
	if _, ok := MaxCVSS([]CVEListMetric{{CVE: "CVE-1"}}); ok {
		t.Error("no scored entry should report absent, not zero")
	}
	if _, ok := MaxCVSS(nil); ok {
		t.Error("empty input should report absent")
	}
}

// The raw field stays for compatibility; this is the typed way to read it.
func TestAuditApplicableAdvisory_CVEMetrics(t *testing.T) {
	adv := &AuditApplicableAdvisory{
		ID: "USN-1",
		CVEListMetrics: []map[string]interface{}{
			{"cve": "CVE-1", "cvss": map[string]interface{}{"score": 8.8},
				"ssvc": map[string]interface{}{
					"options": []interface{}{map[string]interface{}{"Exploitation": "poc"}},
				}},
		},
	}
	metrics, err := adv.CVEMetrics()
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 1 || metrics[0].CVE != "CVE-1" || metrics[0].CVSS.Score != 8.8 {
		t.Fatalf("decode failed: %+v", metrics)
	}
	if metrics[0].SSVC.Exploitation() != SSVCExploitationPOC {
		t.Errorf("SSVC = %q", metrics[0].SSVC.Exploitation())
	}
	if empty, err := (&AuditApplicableAdvisory{}).CVEMetrics(); err != nil || empty != nil {
		t.Errorf("absent metrics should decode to nil, got %v / %v", empty, err)
	}
}

func TestKBAuditV4(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/audit/kb" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		var request kbAuditV4Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.OSName != "Windows Server 2022" || request.OSVersion != "10.0.20348" {
			t.Fatalf("unexpected request: %+v", request)
		}
		if len(request.KBList) != 1 || request.KBList[0] != "KB5041160" {
			t.Fatalf("unexpected kbList: %v", request.KBList)
		}
		_, _ = w.Write([]byte(`{"result":{"totalPackages":1,"items":[{
			"package":"Windows Server 2022","version":"10.0.20348",
			"fixedPackage":"KB5120242",
			"advisories":[{
				"id":"KB5120242","type":"mskb",
				"title":"August 11, 2026-KB5120242 (OS Build 20348.5499)",
				"severity":"Important","msfamily":"Windows",
				"affectedProducts":["Windows Server 2022"],
				"supersedes":["KB5041160","KB5033118"],
				"cvelist":["CVE-2025-59287"],
				"metrics":{"cvss":{"score":9.9}},
				"cvelistMetrics":[{"cve":"CVE-2025-59287","cvss":{"score":9.9},
					"ssvc":{"options":[{"Exploitation":"active"}]}}]
			}]}]}}`))
	})

	result, err := client.Audit().KBAuditV4(
		context.Background(),
		"Windows Server 2022",
		[]string{"KB5041160"},
		WithOSVersion("10.0.20348"),
		WithCVEListMetrics(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalPackages != 1 || len(result.Items) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	item := result.Items[0]
	if item.FixedPackage != "KB5120242" {
		t.Errorf("FixedPackage = %q", item.FixedPackage)
	}
	adv := item.Advisories[0]
	if len(adv.Supersedes) != 2 {
		t.Errorf("Supersedes = %v", adv.Supersedes)
	}
	if adv.Metrics == nil || adv.Metrics.CVSS.Score != 9.9 {
		t.Errorf("advisory metrics = %+v", adv.Metrics)
	}
	if adv.CVEListMetrics[0].SSVC.Exploitation() != SSVCExploitationActive {
		t.Errorf("SSVC = %q", adv.CVEListMetrics[0].SSVC.Exploitation())
	}
}

func TestKBAuditV4_Validation(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("request should not have been sent")
		w.WriteHeader(http.StatusInternalServerError)
	})
	if _, err := client.Audit().KBAuditV4(context.Background(), "", []string{"KB1"}); err == nil {
		t.Error("empty osName should be rejected")
	}
	if _, err := client.Audit().KBAuditV4(context.Background(), "Windows", nil); err == nil {
		t.Error("empty kbList should be rejected")
	}
}

// Records are the shape the API is meant to produce. Bare ids were a server-side
// bug on audit/smart and audit/sbom; it is fixed, but an SDK release cannot
// assume which deployment it is talking to, so both shapes stay parseable.
func TestAdvisoryMetrics_AcceptsBothEPSSShapes(t *testing.T) {
	var records AdvisoryMetrics
	if err := json.Unmarshal([]byte(
		`{"cvss":{"score":9.9},"epss":[{"cve":"CVE-1","epss":0.99,"percentile":0.999,"date":"2026-08-09"}]}`,
	), &records); err != nil {
		t.Fatal(err)
	}
	if records.CVSS.Score != 9.9 || len(records.EPSS) != 1 || records.EPSS[0].Epss != 0.99 {
		t.Fatalf("record shape lost: %+v", records)
	}

	var ids AdvisoryMetrics
	if err := json.Unmarshal([]byte(`{"cvss":{"score":7.5},"epss":["CVE-1","CVE-2"]}`), &ids); err != nil {
		t.Fatal(err)
	}
	if len(ids.EPSS) != 2 || ids.EPSS[0].Cve != "CVE-1" || ids.EPSS[0].Epss != 0 {
		t.Fatalf("degraded shape lost: %+v", ids)
	}

	var empty AdvisoryMetrics
	if err := json.Unmarshal([]byte(`{"cvss":{"score":1}}`), &empty); err != nil || empty.EPSS != nil {
		t.Errorf("absent epss should stay nil: %+v / %v", empty.EPSS, err)
	}
}

// audit/sbom used to be the one endpoint whose metrics.epss was declared
// []string, because it never resolved the stored ids and bare ids were all it
// ever sent. Now it answers like the rest, and the SBOM path has to parse that.
func TestSBOMMetrics_ParsesEPSSRecords(t *testing.T) {
	var metrics SBOMMetrics
	if err := json.Unmarshal([]byte(
		`{"cvss":{"score":10},"epss":[{"cve":"CVE-2021-44228","epss":0.975,"percentile":0.999,"date":"2026-08-11"}]}`,
	), &metrics); err != nil {
		t.Fatalf("sbom metrics must parse EPSS records: %v", err)
	}
	if len(metrics.EPSS) != 1 || metrics.EPSS[0].Cve != "CVE-2021-44228" {
		t.Fatalf("record lost: %+v", metrics.EPSS)
	}
	if metrics.EPSS[0].Epss != 0.975 || metrics.EPSS[0].Percentile != 0.999 {
		t.Fatalf("score or percentile lost: %+v", metrics.EPSS[0])
	}

	// The advisory-level answer carries the highest CVE, not the whole listing.
	if len(metrics.EPSS) > 1 {
		t.Errorf("metrics.epss is a rollup, got %d records", len(metrics.EPSS))
	}

	// Older deployments still send ids on this path; they must not break a client.
	var legacy SBOMMetrics
	if err := json.Unmarshal([]byte(`{"cvss":{"score":10},"epss":["CVE-2021-44228"]}`), &legacy); err != nil {
		t.Fatalf("legacy id shape must still parse: %v", err)
	}
	if len(legacy.EPSS) != 1 || legacy.EPSS[0].Cve != "CVE-2021-44228" {
		t.Fatalf("legacy id lost: %+v", legacy.EPSS)
	}
}

// linux and library advisories carry the rollup now; without it a caller has to
// recompute a severity from the per-CVE entries, which is how every consumer
// ended up with its own max-across-CVEs helper.
func TestPackageAudit_AdvisoryRollupAndOptionReport(t *testing.T) {
	var result PackageAuditResult
	if err := json.Unmarshal([]byte(`{
		"issues":[{"package":"openssl 3.0.13","version":"3.0.13","fixedVersion":"3.0.14",
			"applicableAdvisories":[{"id":"USN-1","match":"<3.0.14","registry":"deb",
				"metrics":{"cvss":{"score":9.8},"epss":[{"cve":"CVE-1","epss":0.4}]},
				"exploitation":{"wildExploited":true},
				"cvelistMetrics":[{"cve":"CVE-1","cvss":{"score":9.8},
					"ssvc":{"options":[{"Exploitation":"active"}]}}]}]}],
		"errors":{},"totalPackages":1,
		"appliedOptions":["metrics","cvelistMetrics"],
		"warnings":[{"option":"exploits","message":"not supported on this endpoint"}]
	}`), &result); err != nil {
		t.Fatal(err)
	}
	adv := &result.Issues[0].ApplicableAdvisories[0]
	if adv.Metrics == nil || adv.Metrics.CVSS.Score != 9.8 {
		t.Fatalf("advisory rollup lost: %+v", adv.Metrics)
	}
	if len(adv.Metrics.EPSS) != 1 || adv.Metrics.EPSS[0].Epss != 0.4 {
		t.Errorf("rollup epss lost: %+v", adv.Metrics.EPSS)
	}
	if adv.Exploitation == nil || !adv.Exploitation.WildExploited {
		t.Errorf("KEV flag lost: %+v", adv.Exploitation)
	}
	metrics, err := adv.CVEMetrics()
	if err != nil || metrics[0].SSVC.Exploitation() != SSVCExploitationActive {
		t.Errorf("ssvc unreachable: %+v / %v", metrics, err)
	}
	if len(result.AppliedOptions) != 2 || result.AppliedOptions[0] != "metrics" {
		t.Errorf("appliedOptions lost: %v", result.AppliedOptions)
	}
	if len(result.Warnings) != 1 || result.Warnings[0].Option != "exploits" {
		t.Errorf("warnings lost: %+v", result.Warnings)
	}
}

// The software and host endpoints return findings through Bulletin, which had
// nowhere to put enrichment - so KEV could not reach a caller on those paths at
// all, however the request was made.
func TestSoftwareAudit_BulletinCarriesEnrichmentAndFix(t *testing.T) {
	var result SoftwareAuditResult
	if err := json.Unmarshal([]byte(`{"items":[{
		"matched_criteria":"cpe:2.3:a:google:chrome:149.0.7827.89",
		"fixed_version":"151.0.7922.138",
		"vulnerabilities":[{"id":"GCSA-1",
			"metrics":{"cvss":{"score":9.6}},
			"exploitation":{"wildExploited":true},
			"cvelistMetrics":[{"cve":"CVE-2026-11645",
				"ssvc":{"options":[{"Exploitation":"active"}]}}]}]}]}`), &result); err != nil {
		t.Fatal(err)
	}
	item := result.Items[0]
	if item.FixedVersion != "151.0.7922.138" {
		t.Errorf("fixed_version lost: %q", item.FixedVersion)
	}
	b := item.Vulnerabilities[0]
	if b.Metrics == nil || b.Metrics.CVSS.Score != 9.6 {
		t.Fatalf("bulletin metrics lost: %+v", b.Metrics)
	}
	if b.Exploitation == nil || !b.Exploitation.WildExploited {
		t.Errorf("bulletin KEV lost: %+v", b.Exploitation)
	}
	if len(b.CVEListMetrics) != 1 || b.CVEListMetrics[0].SSVC.Exploitation() != SSVCExploitationActive {
		t.Errorf("bulletin ssvc lost: %+v", b.CVEListMetrics)
	}
}

// sbom advisories gain the per-CVE breakdown they lacked.
func TestSBOMAudit_PerCVEBreakdownAndOptionReport(t *testing.T) {
	var result SBOMAuditResult
	if err := json.Unmarshal([]byte(`{"data":[{"package":"requests 2.19.1",
		"applicableAdvisories":[{"id":"GHSA-1","type":"ghsa","match":"<2.20.0",
			"title":"t","description":"d","published":"2018-01-01T00:00:00",
			"cvelistMetrics":[{"cve":"CVE-2018-18074","cvss":{"score":7.5},
				"ssvc":{"options":[{"Exploitation":"poc"}]}}]}]}],
		"totalPackages":1,"appliedOptions":["cvelistMetrics"],"warnings":[]}`), &result); err != nil {
		t.Fatal(err)
	}
	adv := result.Packages[0].ApplicableAdvisories[0]
	if len(adv.CVEListMetrics) != 1 || adv.CVEListMetrics[0].CVE != "CVE-2018-18074" {
		t.Fatalf("per-CVE breakdown lost: %+v", adv.CVEListMetrics)
	}
	if adv.CVEListMetrics[0].SSVC.Exploitation() != SSVCExploitationPOC {
		t.Errorf("ssvc lost: %+v", adv.CVEListMetrics[0].SSVC)
	}
	if len(result.AppliedOptions) != 1 {
		t.Errorf("appliedOptions lost: %v", result.AppliedOptions)
	}
}

// The boolean switch was sent but `fields` was not, so the advisory rollup could
// not be requested from here at all - the same silent drop the API itself was
// fixed for, one layer up.
func TestPackageAudits_SendFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		call func(*Client) error
	}{
		{"linux", "/api/v4/audit/linux", func(c *Client) error {
			_, err := c.Audit().LinuxAuditV4(context.Background(), "ubuntu", "24.04",
				[]string{"openssl 3.0.13"}, WithAuditFields("metrics"))
			return err
		}},
		{"library", "/api/v4/audit/library", func(c *Client) error {
			_, err := c.Audit().LibraryAudit(context.Background(),
				[]string{"pkg:pypi/requests@2.19.1"}, WithAuditFields("metrics"))
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sent []string
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				var request struct {
					Fields []string `json:"fields"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatal(err)
				}
				sent = request.Fields
				_, _ = w.Write([]byte(`{"result":{"issues":[],"errors":{},"totalPackages":0}}`))
			})
			if err := tc.call(client); err != nil {
				t.Fatal(err)
			}
			if len(sent) != 1 || sent[0] != "metrics" {
				t.Errorf("fields not sent: %v", sent)
			}
		})
	}
}
