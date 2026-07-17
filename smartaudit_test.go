package vulners

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestAuditService_SmartAudit(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v4/audit/smart" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}

		var request smartAuditRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if len(request.Software) != 1 || request.Software[0] != "OpenSSL 1.0.1" {
			t.Fatalf("unexpected software: %v", request.Software)
		}
		if request.Catalog != "extended" {
			t.Fatalf("unexpected catalog: %q", request.Catalog)
		}

		response := `{
			"result": [{
				"input": "OpenSSL 1.0.1",
				"cpe": "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*",
				"purls": ["pkg:generic/openssl@1.0.1"],
				"confidence": 0.91,
				"vulnerabilities": [{
					"id": "CVE-2014-0160",
					"reasons": [{
						"config": "nvd",
						"criterias": [[{
							"criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
							"vulnerable": true,
							"versionEndExcluding": "1.0.1g"
						}]]
					}],
					"title": "CVE-2014-0160",
					"short_description": "OpenSSL information disclosure vulnerability.",
					"type": "cve",
					"href": "https://vulners.com/cve/CVE-2014-0160",
					"published": "2014-04-07T00:00:00",
					"modified": "2025-04-03T00:00:00",
					"ai_score": {"value": 7.5, "uncertainty": 0.5}
				}]
			}]
		}`
		_, _ = w.Write([]byte(response))
	})

	result, err := client.Audit().SmartAudit(
		context.Background(),
		[]string{"OpenSSL 1.0.1"},
		WithAuditCatalog("extended"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(result.Items))
	}

	item := result.Items[0]
	if item.Input != "OpenSSL 1.0.1" || item.Confidence != 0.91 {
		t.Fatalf("unexpected Smart Audit item: %+v", item)
	}
	if len(item.PURLs) != 1 || item.PURLs[0] != "pkg:generic/openssl@1.0.1" {
		t.Fatalf("unexpected pURLs: %v", item.PURLs)
	}
	if len(item.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(item.Vulnerabilities))
	}

	vulnerability := item.Vulnerabilities[0]
	if vulnerability.ID != "CVE-2014-0160" || vulnerability.AIScore == nil || vulnerability.AIScore.Value != 7.5 {
		t.Fatalf("unexpected vulnerability: %+v", vulnerability)
	}
	if vulnerability.Published == nil || vulnerability.Published.Year() != 2014 {
		t.Fatalf("unexpected published time: %v", vulnerability.Published)
	}
	if len(vulnerability.Reasons) != 1 || len(vulnerability.Reasons[0].Criteria) != 1 {
		t.Fatalf("unexpected match reasons: %v", vulnerability.Reasons)
	}
	criterion := vulnerability.Reasons[0].Criteria[0][0]
	if !criterion.Vulnerable || criterion.VersionEndExcluding != "1.0.1g" {
		t.Fatalf("unexpected criterion: %+v", criterion)
	}
}

func TestAuditService_SmartAuditValidation(t *testing.T) {
	client := newTestClient(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("unexpected request")
	})

	tests := []struct {
		name     string
		software []string
		opts     []AuditOption
	}{
		{name: "missing software"},
		{name: "too many items", software: make([]string, maxSmartAuditItems+1)},
		{name: "empty item", software: []string{""}},
		{name: "item too long", software: []string{strings.Repeat("a", maxSmartAuditItemLength+1)}},
		{name: "invalid catalog", software: []string{"nginx 1.14"}, opts: []AuditOption{WithAuditCatalog("custom")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.Audit().SmartAudit(context.Background(), tt.software, tt.opts...)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("expected ErrInvalidInput, got %v", err)
			}
		})
	}
}

func TestAuditService_SmartAuditAccepts512UnicodeCharacters(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result": []}`))
	})

	_, err := client.Audit().SmartAudit(
		context.Background(),
		[]string{strings.Repeat("П", maxSmartAuditItemLength)},
	)
	if err != nil {
		t.Fatal(err)
	}
}
