package vulners

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Helper to create a test client with a mock server
func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client, err := NewClient("test-key",
		WithBaseURL(server.URL),
		WithAllowInsecure(),
		WithRateLimit(100, 100),
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// Helper to create a JSON response handler
func jsonHandler(t *testing.T, data interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := apiResponse{
			Result: "OK",
		}
		if data != nil {
			dataBytes, err := json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			resp.Data = dataBytes
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatal(err)
		}
	}
}

func TestArchiveService_FetchCollection(t *testing.T) {
	expectedBulletins := []Bulletin{
		{ID: "CVE-2021-44228", Title: "Log4Shell"},
		{ID: "CVE-2021-45046", Title: "Log4j 2.x vulnerability"},
	}

	data := map[string]interface{}{
		"bulletins": expectedBulletins,
		"total":     2,
	}

	client := newTestClient(t, jsonHandler(t, data))

	bulletins, err := client.Archive().FetchCollection(context.Background(), CollectionCVE)
	if err != nil {
		t.Fatal(err)
	}

	if len(bulletins) != 2 {
		t.Errorf("expected 2 bulletins, got %d", len(bulletins))
	}

	if bulletins[0].ID != "CVE-2021-44228" {
		t.Errorf("expected ID=CVE-2021-44228, got %s", bulletins[0].ID)
	}
}

func TestArchiveService_FetchCollectionUpdate(t *testing.T) {
	data := map[string]interface{}{
		"bulletins": []Bulletin{{ID: "CVE-2021-44228"}},
		"total":     1,
	}

	client := newTestClient(t, jsonHandler(t, data))

	since := time.Now().Add(-24 * time.Hour)
	bulletins, err := client.Archive().FetchCollectionUpdate(context.Background(), CollectionCVE, since)
	if err != nil {
		t.Fatal(err)
	}

	if len(bulletins) != 1 {
		t.Errorf("expected 1 bulletin, got %d", len(bulletins))
	}
}

func TestWebhookService_List(t *testing.T) {
	data := map[string]interface{}{
		"webhooks": []Webhook{
			{ID: "webhook-1", Query: "type:cve", Active: true},
			{ID: "webhook-2", Query: "type:exploit", Active: false},
		},
	}

	client := newTestClient(t, jsonHandler(t, data))

	webhooks, err := client.Webhook().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(webhooks) != 2 {
		t.Errorf("expected 2 webhooks, got %d", len(webhooks))
	}

	if webhooks[0].ID != "webhook-1" {
		t.Errorf("expected ID=webhook-1, got %s", webhooks[0].ID)
	}
}

func TestWebhookService_Add(t *testing.T) {
	data := Webhook{ID: "new-webhook", Query: "type:cve AND cvss.score:[9 TO 10]", Active: true}

	client := newTestClient(t, jsonHandler(t, data))

	webhook, err := client.Webhook().Add(context.Background(), "type:cve AND cvss.score:[9 TO 10]")
	if err != nil {
		t.Fatal(err)
	}

	if webhook.ID != "new-webhook" {
		t.Errorf("expected ID=new-webhook, got %s", webhook.ID)
	}

	if !webhook.Active {
		t.Error("expected Active=true")
	}
}

func TestWebhookService_AddEmptyQuery(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Webhook().Add(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty query")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestWebhookService_Enable(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	err := client.Webhook().Enable(context.Background(), "webhook-1", true)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWebhookService_EnableEmptyID(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	err := client.Webhook().Enable(context.Background(), "", true)
	if err == nil {
		t.Error("expected error for empty id")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestWebhookService_Delete(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	err := client.Webhook().Delete(context.Background(), "webhook-1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestWebhookService_Read(t *testing.T) {
	data := WebhookData{
		ID:       "webhook-1",
		Data:     []Bulletin{{ID: "CVE-2021-44228"}},
		NewCount: 1,
	}

	client := newTestClient(t, jsonHandler(t, data))

	webhookData, err := client.Webhook().Read(context.Background(), "webhook-1", true)
	if err != nil {
		t.Fatal(err)
	}

	if webhookData.NewCount != 1 {
		t.Errorf("expected NewCount=1, got %d", webhookData.NewCount)
	}
}

func TestSubscriptionService_List(t *testing.T) {
	data := map[string]interface{}{
		"subscriptions": []Subscription{
			{ID: "sub-1", Name: "Critical CVEs", Active: true},
		},
	}

	client := newTestClient(t, jsonHandler(t, data))

	subs, err := client.Subscription().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(subs) != 1 {
		t.Errorf("expected 1 subscription, got %d", len(subs))
	}

	if subs[0].ID != "sub-1" {
		t.Errorf("expected ID=sub-1, got %s", subs[0].ID)
	}
}

func TestSubscriptionService_Get(t *testing.T) {
	data := Subscription{ID: "sub-1", Name: "Critical CVEs", Active: true}

	client := newTestClient(t, jsonHandler(t, data))

	sub, err := client.Subscription().Get(context.Background(), "sub-1")
	if err != nil {
		t.Fatal(err)
	}

	if sub.ID != "sub-1" {
		t.Errorf("expected ID=sub-1, got %s", sub.ID)
	}
}

func TestSubscriptionService_GetEmptyID(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Subscription().Get(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty id")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestSubscriptionService_Create(t *testing.T) {
	data := Subscription{ID: "new-sub", Name: "New Subscription", Active: true}

	client := newTestClient(t, jsonHandler(t, data))

	req := &SubscriptionRequest{Name: "New Subscription", Type: "webhook"}
	sub, err := client.Subscription().Create(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	if sub.ID != "new-sub" {
		t.Errorf("expected ID=new-sub, got %s", sub.ID)
	}
}

func TestSubscriptionService_CreateNilRequest(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Subscription().Create(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil request")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestSubscriptionService_Update(t *testing.T) {
	data := Subscription{ID: "sub-1", Name: "Updated", Active: true}

	client := newTestClient(t, jsonHandler(t, data))

	req := &SubscriptionRequest{Name: "Updated"}
	sub, err := client.Subscription().Update(context.Background(), "sub-1", req)
	if err != nil {
		t.Fatal(err)
	}

	if sub.Name != "Updated" {
		t.Errorf("expected Name=Updated, got %s", sub.Name)
	}
}

func TestSubscriptionService_Delete(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		resp := apiResponse{Result: "OK"}
		_ = json.NewEncoder(w).Encode(resp)
	})

	err := client.Subscription().Delete(context.Background(), "sub-1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSubscriptionService_Enable(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	err := client.Subscription().Enable(context.Background(), "sub-1", true)
	if err != nil {
		t.Fatal(err)
	}
}

func TestStixService_MakeBundleByID(t *testing.T) {
	data := StixBundle{
		Type: "bundle",
		ID:   "bundle--12345",
	}

	client := newTestClient(t, jsonHandler(t, data))

	bundle, err := client.Stix().MakeBundleByID(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatal(err)
	}

	if bundle.Type != "bundle" {
		t.Errorf("expected Type=bundle, got %s", bundle.Type)
	}

	if bundle.ID != "bundle--12345" {
		t.Errorf("expected ID=bundle--12345, got %s", bundle.ID)
	}
}

func TestStixService_MakeBundleByIDEmptyID(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Stix().MakeBundleByID(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty bulletinID")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestStixService_MakeBundleByCVE(t *testing.T) {
	data := StixBundle{
		Type: "bundle",
		ID:   "bundle--67890",
	}

	client := newTestClient(t, jsonHandler(t, data))

	bundle, err := client.Stix().MakeBundleByCVE(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatal(err)
	}

	if bundle.Type != "bundle" {
		t.Errorf("expected Type=bundle, got %s", bundle.Type)
	}
}

func TestReportService_VulnsSummaryReport(t *testing.T) {
	data := VulnsSummary{
		Total:    100,
		Critical: 10,
		High:     30,
		Medium:   40,
		Low:      20,
	}

	client := newTestClient(t, jsonHandler(t, data))

	summary, err := client.Report().VulnsSummaryReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if summary.Total != 100 {
		t.Errorf("expected Total=100, got %d", summary.Total)
	}

	if summary.Critical != 10 {
		t.Errorf("expected Critical=10, got %d", summary.Critical)
	}
}

func TestReportService_VulnsList(t *testing.T) {
	data := []VulnItem{
		{ID: "vuln-1", Title: "Vuln 1", Severity: "critical", CVSS: 9.8},
		{ID: "vuln-2", Title: "Vuln 2", Severity: "high", CVSS: 7.5},
	}

	client := newTestClient(t, jsonHandler(t, data))

	vulns, err := client.Report().VulnsList(context.Background(),
		WithReportLimit(50),
		WithReportOffset(0),
		WithReportSort("cvss", false),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(vulns) != 2 {
		t.Errorf("expected 2 vulns, got %d", len(vulns))
	}

	if vulns[0].Severity != "critical" {
		t.Errorf("expected Severity=critical, got %s", vulns[0].Severity)
	}
}

func TestReportService_IPSummaryReport(t *testing.T) {
	data := IPSummary{
		Total:     50,
		WithVulns: 30,
		Critical:  5,
	}

	client := newTestClient(t, jsonHandler(t, data))

	summary, err := client.Report().IPSummaryReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if summary.Total != 50 {
		t.Errorf("expected Total=50, got %d", summary.Total)
	}

	if summary.WithVulns != 30 {
		t.Errorf("expected WithVulns=30, got %d", summary.WithVulns)
	}
}

func TestReportService_ScanList(t *testing.T) {
	data := []ScanItem{
		{ID: "scan-1", Name: "Scan 1", Status: "completed"},
	}

	client := newTestClient(t, jsonHandler(t, data))

	scans, err := client.Report().ScanList(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(scans) != 1 {
		t.Errorf("expected 1 scan, got %d", len(scans))
	}

	if scans[0].Status != "completed" {
		t.Errorf("expected Status=completed, got %s", scans[0].Status)
	}
}

func TestReportService_HostVulns(t *testing.T) {
	data := []HostVuln{
		{ID: "hv-1", Host: "192.168.1.1", VulnID: "CVE-2021-44228"},
	}

	client := newTestClient(t, jsonHandler(t, data))

	hostVulns, err := client.Report().HostVulns(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(hostVulns) != 1 {
		t.Errorf("expected 1 host vuln, got %d", len(hostVulns))
	}

	if hostVulns[0].Host != "192.168.1.1" {
		t.Errorf("expected Host=192.168.1.1, got %s", hostVulns[0].Host)
	}
}

func TestMiscService_SearchCPE(t *testing.T) {
	data := map[string]interface{}{
		"best_match": "cpe:2.3:a:google:chrome:96.0.4664.110:*:*:*:*:*:*:*",
		"cpe": []string{
			"cpe:2.3:a:google:chrome:96.0.4664.110:*:*:*:*:*:*:*",
			"cpe:2.3:a:google:chrome:96.0.4664.93:*:*:*:*:*:*:*",
		},
	}

	client := newTestClient(t, jsonHandler(t, data))

	result, err := client.Misc().SearchCPE(context.Background(), "chrome", "google")
	if err != nil {
		t.Fatal(err)
	}

	if len(result.CPEs) != 2 {
		t.Errorf("expected 2 CPEs, got %d", len(result.CPEs))
	}

	if result.BestMatch == "" {
		t.Error("expected non-empty BestMatch")
	}
}

func TestMiscService_SearchCPEEmptyProduct(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Misc().SearchCPE(context.Background(), "", "google")
	if err == nil {
		t.Error("expected error for empty product")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestMiscService_SearchCPEEmptyVendor(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Misc().SearchCPE(context.Background(), "chrome", "")
	if err == nil {
		t.Error("expected error for empty vendor")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestMiscService_GetAIScore(t *testing.T) {
	data := map[string]interface{}{
		"score": map[string]interface{}{
			"value":       8.5,
			"uncertainty": 0.2,
		},
	}

	client := newTestClient(t, jsonHandler(t, data))

	score, err := client.Misc().GetAIScore(context.Background(), "Apache Log4j vulnerability")
	if err != nil {
		t.Fatal(err)
	}

	if score == nil {
		t.Fatal("expected non-nil score")
	}

	if score.Value != 8.5 {
		t.Errorf("expected Value=8.5, got %f", score.Value)
	}
}

func TestMiscService_GetAIScoreEmptyText(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Misc().GetAIScore(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty text")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestMiscService_GetSuggestion(t *testing.T) {
	data := map[string]interface{}{
		"suggestions": []string{"type", "title", "description"},
	}

	client := newTestClient(t, jsonHandler(t, data))

	suggestions, err := client.Misc().GetSuggestion(context.Background(), "bulletinFamily")
	if err != nil {
		t.Fatal(err)
	}

	if len(suggestions) != 3 {
		t.Errorf("expected 3 suggestions, got %d", len(suggestions))
	}
}

func TestMiscService_GetSuggestionEmptyField(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Misc().GetSuggestion(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty fieldName")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestMiscService_QueryAutocomplete(t *testing.T) {
	// Test various autocomplete response formats
	tests := []struct {
		name string
		data map[string]interface{}
	}{
		{
			name: "string array",
			data: map[string]interface{}{
				"suggestions": []string{"log4j", "log4shell", "logging"},
			},
		},
		{
			name: "nested array",
			data: map[string]interface{}{
				"autocomplete": [][]interface{}{
					{"log4j", false},
					{"log4shell", false},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, jsonHandler(t, tt.data))

			suggestions, err := client.Misc().QueryAutocomplete(context.Background(), "log4")
			if err != nil {
				t.Fatal(err)
			}

			if len(suggestions) == 0 {
				t.Error("expected non-empty suggestions")
			}
		})
	}
}

func TestSearchService_GetBulletinEmptyID(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Search().GetBulletin(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty id")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestSearchService_GetBulletinReferencesEmptyID(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Search().GetBulletinReferences(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty id")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestSearchService_GetBulletinHistoryEmptyID(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Search().GetBulletinHistory(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty id")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestAuditService_SBOMAudit(t *testing.T) {
	sbomContent := `{"bomFormat":"CycloneDX","specVersion":"1.4"}`

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// Validate request method
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		// Validate content type is multipart
		ct := r.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(ct)
		if err != nil {
			t.Fatalf("failed to parse Content-Type: %v", err)
		}
		if mediaType != "multipart/form-data" {
			t.Errorf("expected multipart/form-data, got %s", mediaType)
		}

		// Read the multipart form and validate the file field
		mr := multipart.NewReader(r.Body, params["boundary"])
		part, err := mr.NextPart()
		if err != nil {
			t.Fatalf("failed to read multipart part: %v", err)
		}
		if part.FormName() != "file" {
			t.Errorf("expected form field 'file', got '%s'", part.FormName())
		}
		if part.FileName() != "sbom" {
			t.Errorf("expected filename 'sbom', got '%s'", part.FileName())
		}
		body, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("failed to read part body: %v", err)
		}
		if string(body) != sbomContent {
			t.Errorf("expected body %q, got %q", sbomContent, string(body))
		}

		// Return SBOM audit response (v4 format: {"result": [...]})
		fixed := "1.5.0"
		resp := SBOMAuditResult{
			Packages: []SBOMPackageResult{
				{
					Package:      "log4j-core",
					Version:      "2.14.1",
					FixedVersion: &fixed,
					ApplicableAdvisories: []SBOMAdvisory{
						{
							ID:          "CVE-2021-44228",
							Type:        "cve",
							Match:       "range",
							Title:       "Log4Shell",
							Description: "Remote code execution in Apache Log4j",
							EPSS: []Epss{
								{Cve: "CVE-2021-44228", Epss: 0.975, Percentile: 0.999},
							},
							AIScore: &AIScore{
								Value:       9.8,
								Uncertainty: 0.1,
							},
							Metrics: &SBOMMetrics{
								CVSS: &CVSS{Score: 10.0, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
							},
							Exploitation: &Exploitation{
								WildExploited: true,
								WildExploitedSources: []ExploitationSource{
									{Type: "CISA KEV", IDList: []string{"CVE-2021-44228"}},
								},
							},
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatal(err)
		}
	})

	result, err := client.Audit().SBOMAudit(context.Background(), bytes.NewBufferString(sbomContent))
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(result.Packages))
	}
	pkg := result.Packages[0]
	if pkg.Package != "log4j-core" {
		t.Errorf("expected Package=log4j-core, got %s", pkg.Package)
	}
	if pkg.Version != "2.14.1" {
		t.Errorf("expected Version=2.14.1, got %s", pkg.Version)
	}
	if pkg.FixedVersion == nil || *pkg.FixedVersion != "1.5.0" {
		t.Errorf("expected FixedVersion=1.5.0, got %v", pkg.FixedVersion)
	}
	if len(pkg.ApplicableAdvisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(pkg.ApplicableAdvisories))
	}
	adv := pkg.ApplicableAdvisories[0]
	if adv.ID != "CVE-2021-44228" {
		t.Errorf("expected advisory ID=CVE-2021-44228, got %s", adv.ID)
	}
	// EPSS
	if len(adv.EPSS) != 1 || adv.EPSS[0].Epss != 0.975 {
		t.Errorf("expected EPSS[0].Epss=0.975, got %v", adv.EPSS)
	}
	// AIScore
	if adv.AIScore == nil || adv.AIScore.Value != 9.8 {
		t.Errorf("expected AIScore.Value=9.8, got %v", adv.AIScore)
	}
	// Metrics
	if adv.Metrics == nil || adv.Metrics.CVSS == nil || adv.Metrics.CVSS.Score != 10.0 {
		t.Errorf("expected Metrics.CVSS.Score=10.0, got %v", adv.Metrics)
	}
	// Exploitation
	if adv.Exploitation == nil || !adv.Exploitation.WildExploited {
		t.Errorf("expected Exploitation.WildExploited=true, got %v", adv.Exploitation)
	}
	if adv.Exploitation != nil && (len(adv.Exploitation.WildExploitedSources) != 1 || adv.Exploitation.WildExploitedSources[0].Type != "CISA KEV") {
		t.Errorf("expected WildExploitedSources[0].Type=CISA KEV, got %v", adv.Exploitation.WildExploitedSources)
	}
}

func TestAuditService_SBOMAuditNilReader(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Audit().SBOMAudit(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil reader")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestAuditService_HostEmptyOS(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Audit().Host(context.Background(), "", "20.04", nil)
	if err == nil {
		t.Error("expected error for empty os")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestAuditService_LinuxAuditEmptyOS(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Audit().LinuxAudit(context.Background(), "", "20.04", nil)
	if err == nil {
		t.Error("expected error for empty osName")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestAuditService_KBAuditEmptyOS(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Audit().KBAudit(context.Background(), "", nil)
	if err == nil {
		t.Error("expected error for empty os")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestAuditService_WinAuditEmptyOS(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Audit().WinAudit(context.Background(), "", "", nil, nil)
	if err == nil {
		t.Error("expected error for empty os")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}
