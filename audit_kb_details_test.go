package vulners

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// KBAudit must request per-CVE details ("details": true) and surface the
// returned "details" objects (id/cvss/cvelist) as scored Vulnerabilities,
// not just the flat cvelist.
func TestAuditService_KBAuditDetails(t *testing.T) {
	data := map[string]any{
		"kbLatest": "KB5077181",
		"kbMissed": []any{},
		"cvelist":  []string{"CVE-2026-1", "CVE-2026-2"},
		"details": []map[string]any{
			{"id": "CVE-2026-1", "cvelist": []string{"CVE-2026-1"}, "cvss": map[string]any{"score": 7.5, "vector": "AV:N/AC:L"}},
			{"id": "CVE-2026-2", "cvelist": []string{"CVE-2026-2"}, "cvss": map[string]any{"score": 9.8}},
		},
	}

	respond := jsonHandler(t, data)
	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req["details"] != true {
			t.Errorf("request details = %v, want true", req["details"])
		}
		respond(w, r)
	}
	client := newTestClient(t, handler)

	res, err := client.Audit().KBAudit(context.Background(), "Windows", []string{"KB5000001"})
	if err != nil {
		t.Fatalf("KBAudit: %v", err)
	}
	if len(res.Vulnerabilities) != 2 {
		t.Fatalf("Vulnerabilities = %d, want 2", len(res.Vulnerabilities))
	}

	byID := map[string]Vulnerability{}
	for _, v := range res.Vulnerabilities {
		if v.CVSS == nil {
			t.Fatalf("vulnerability %q has no CVSS", v.BulletinID)
		}
		byID[v.BulletinID] = v
	}
	if got := byID["CVE-2026-1"].CVSS.Score; got != 7.5 {
		t.Errorf("CVE-2026-1 score = %v, want 7.5", got)
	}
	if got := byID["CVE-2026-2"].CVSS.Score; got != 9.8 {
		t.Errorf("CVE-2026-2 score = %v, want 9.8", got)
	}
}
