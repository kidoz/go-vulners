package vulners

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestSearchService_SearchBulletinsUnwrapsSource(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, map[string]interface{}{
		"search": []map[string]interface{}{
			{"_source": map[string]interface{}{"id": "CVE-2025-0001", "title": "example"}},
		},
		"total":         1,
		"maxSearchSize": 100,
	}))

	result, err := client.Search().SearchBulletins(context.Background(), "id:CVE-2025-0001")
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || len(result.Bulletins) != 1 || result.Bulletins[0].ID != "CVE-2025-0001" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestSearchService_GetBulletinReferencesUsesIDEndpoint(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/search/id/" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var request idSearchRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if !request.References {
			t.Fatal("expected references=true")
		}

		response := apiResponse{Result: "OK"}
		response.Data = json.RawMessage(`{
			"documents": {},
			"references": {
				"CVE-2025-0001": {
					"cve": [{"id": "CVE-2025-0002"}],
					"exploit": [{"id": "EXPLOIT-2"}, {"id": "EXPLOIT-1"}]
				}
			}
		}`)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	})

	references, err := client.Search().GetBulletinReferences(context.Background(), "CVE-2025-0001")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"CVE-2025-0002", "EXPLOIT-1", "EXPLOIT-2"}
	if len(references) != len(want) {
		t.Fatalf("unexpected references: %v", references)
	}
	for i := range want {
		if references[i] != want[i] {
			t.Fatalf("unexpected references: %v", references)
		}
	}
}

func TestSearchService_GetBulletinHistoryUnwrapsResult(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, map[string]interface{}{
		"result": []map[string]interface{}{
			{"field": "title", "value": "new title", "published": "2026-06-12T10:00:00"},
		},
	}))

	history, err := client.Search().GetBulletinHistory(context.Background(), "CVE-2025-0001")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].Field != "title" || string(history[0].Value) != `"new title"` {
		t.Fatalf("unexpected history: %+v", history)
	}
}

func TestSearchService_SearchExploitsAll(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var request searchRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Query != "bulletinFamily:exploit AND (CVE-2025-0001)" {
			t.Fatalf("unexpected query: %s", request.Query)
		}

		response := apiResponse{Result: "OK"}
		response.Data = json.RawMessage(`{"search":[],"total":0,"maxSearchSize":100}`)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	})

	result, err := client.Search().SearchExploitsAll(
		context.Background(),
		"CVE-2025-0001",
		WithLimit(10),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected no results, got %d", len(result))
	}
}

func TestSearchService_GetMultipleBulletinsWithReferences(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, map[string]interface{}{
		"documents": map[string]interface{}{
			"CVE-2025-0001": map[string]interface{}{"id": "CVE-2025-0001"},
		},
		"references": map[string]interface{}{
			"CVE-2025-0001": map[string]interface{}{
				"exploit": []map[string]interface{}{{"id": "EXPLOIT-1"}},
			},
		},
	}))

	result, err := client.Search().GetMultipleBulletinsWithReferences(
		context.Background(),
		[]string{"CVE-2025-0001"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Documents["CVE-2025-0001"].ID != "CVE-2025-0001" {
		t.Fatalf("unexpected documents: %+v", result.Documents)
	}
	if result.References["CVE-2025-0001"]["exploit"][0].ID != "EXPLOIT-1" {
		t.Fatalf("unexpected references: %+v", result.References)
	}
}

func TestSearchService_GetKBSeeds(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, map[string]interface{}{
		"documents": map[string]interface{}{
			"MSKB-5000001": map[string]interface{}{
				"id":          "MSKB-5000001",
				"superseeds":  []string{"MSKB-4000001"},
				"parentseeds": []string{"MSKB-6000001"},
			},
		},
	}))

	result, err := client.Search().GetKBSeeds(context.Background(), "MSKB-5000001")
	if err != nil {
		t.Fatal(err)
	}
	if result.Superseeds[0] != "MSKB-4000001" || result.Parentseeds[0] != "MSKB-6000001" {
		t.Fatalf("unexpected seeds: %+v", result)
	}
}

func TestSearchService_GetWebVulnerabilities(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/search/web-vulns/" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var request webVulnerabilityRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Match != "full" || request.Catalog != "extended" || len(request.Paths) != 1 {
			t.Fatalf("unexpected request: %+v", request)
		}

		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"/admin": []map[string]interface{}{
					{
						"id":   "WEB-2025-0001",
						"type": "web",
						"webApplicability": map[string]interface{}{
							"applicable": true,
							"vulnerabilities": []map[string]interface{}{
								{"parameter": "id", "url": "/admin", "position": "query", "description": "example", "cwe": []string{"CWE-89"}},
							},
						},
						"metrics":  map[string]interface{}{},
						"exploits": []string{},
					},
				},
			},
		}); err != nil {
			t.Fatal(err)
		}
	})

	result, err := client.Search().GetWebVulnerabilities(
		context.Background(),
		[]string{"/admin"},
		"cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*",
		WithWebVulnerabilityMatch("full"),
		WithWebVulnerabilityCatalog("extended"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result["/admin"]) != 1 || result["/admin"][0].ID != "WEB-2025-0001" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestSearchService_GetWebVulnerabilitiesRequiresPaths(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Search().GetWebVulnerabilities(context.Background(), nil, nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}
