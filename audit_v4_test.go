package vulners

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestAuditItem_MarshalLegacyFields(t *testing.T) {
	data, err := json.Marshal(AuditItem{Software: "nginx", Version: "1.18.0", Type: "software"})
	if err != nil {
		t.Fatal(err)
	}

	var criteria map[string]interface{}
	if err := json.Unmarshal(data, &criteria); err != nil {
		t.Fatal(err)
	}
	if criteria["product"] != "nginx" || criteria["part"] != "a" {
		t.Fatalf("unexpected criteria: %s", data)
	}
	if _, ok := criteria["software"]; ok {
		t.Fatalf("legacy software field leaked onto the wire: %s", data)
	}
}

func TestAuditService_SoftwareV4Request(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var request softwareAuditRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Software[0].Product != "nginx" || request.Match != "full" || request.Catalog != "extended" {
			t.Fatalf("unexpected request: %+v", request)
		}
		if len(request.Fields) != 2 || len(request.Config) != 1 {
			t.Fatalf("unexpected request options: %+v", request)
		}
		if err := json.NewEncoder(w).Encode(map[string]interface{}{"result": []interface{}{}}); err != nil {
			t.Fatal(err)
		}
	})

	_, err := client.Audit().Software(
		context.Background(),
		[]AuditItem{{Part: "a", Product: "nginx", Version: "1.18.0"}},
		WithAuditMatch("full"),
		WithAuditCatalog("extended"),
		WithAuditFields("title", "cvelist"),
		WithAuditConfig("software"),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuditService_HostV4Request(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var request hostAuditRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.OperatingSystem.Part != "o" || request.OperatingSystem.Product != "ubuntu" || request.OperatingSystem.Version != "24.04" {
			t.Fatalf("unexpected operating system criteria: %+v", request.OperatingSystem)
		}
		if len(request.Software) != 1 || request.Software[0].Product != "nginx" {
			t.Fatalf("unexpected software criteria: %+v", request.Software)
		}
		if err := json.NewEncoder(w).Encode(map[string]interface{}{"result": []interface{}{}}); err != nil {
			t.Fatal(err)
		}
	})

	_, err := client.Audit().Host(
		context.Background(),
		"ubuntu",
		"24.04",
		[]AuditItem{{Part: "a", Product: "nginx", Version: "1.18.0"}},
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuditService_LinuxAuditV4(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v4/audit/linux" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}

		var request linuxAuditV4Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.OSName != "ubuntu" || request.OSVersion != "24.04" || request.OSArch != "amd64" {
			t.Fatalf("unexpected OS request: %+v", request)
		}
		if !request.IncludeUnofficial || !request.IncludeCandidates || !request.CVEListMetrics {
			t.Fatalf("audit options were not applied: %+v", request)
		}

		response := map[string]interface{}{
			"result": map[string]interface{}{
				"issues": []map[string]interface{}{
					{
						"package":      "openssl",
						"version":      "3.0.2",
						"fixedVersion": "3.0.2-0ubuntu1.20",
						"fixedPackage": "openssl-3.0.2-0ubuntu1.20",
						"applicableAdvisories": []map[string]interface{}{
							{"id": "UBUNTU-CVE-2025-0001", "match": "pkg:deb/ubuntu/openssl@3.0.2"},
						},
					},
				},
				"errors":        map[string]string{},
				"totalPackages": 1,
			},
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	})

	result, err := client.Audit().LinuxAuditV4(
		context.Background(),
		"ubuntu",
		"24.04",
		[]string{"openssl 3.0.2"},
		WithOSArch("amd64"),
		WithIncludeUnofficial(true),
		WithIncludeCandidates(true),
		WithCVEListMetrics(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalPackages != 1 || len(result.Issues) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Issues[0].ApplicableAdvisories[0].ID != "UBUNTU-CVE-2025-0001" {
		t.Fatalf("unexpected advisory: %+v", result.Issues[0].ApplicableAdvisories[0])
	}
}

func TestAuditService_LibraryAudit(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/audit/library" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var request libraryAuditRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if len(request.Packages) != 1 || request.Packages[0] != "pkg:golang/golang.org/x/text@v0.3.0" {
			t.Fatalf("unexpected packages: %v", request.Packages)
		}
		if !request.IncludeAnyVersion {
			t.Fatal("expected includeAnyVersion=true")
		}

		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{"issues": []interface{}{}, "errors": map[string]string{}, "totalPackages": 1},
		}); err != nil {
			t.Fatal(err)
		}
	})

	result, err := client.Audit().LibraryAudit(
		context.Background(),
		[]string{"pkg:golang/golang.org/x/text@v0.3.0"},
		WithIncludeAnyVersion(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalPackages != 1 {
		t.Fatalf("expected one package, got %d", result.TotalPackages)
	}
}

func TestAuditService_CVEAudit(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/audit/cve" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"cve": "CVE-2025-0001",
				"affectedPackages": []map[string]interface{}{
					{"id": "pkg:maven/example@1.0", "name": "example", "range": "<2.0", "registry": "maven"},
				},
				"affectedCpe": []interface{}{},
			},
		}); err != nil {
			t.Fatal(err)
		}
	})

	result, err := client.Audit().CVEAudit(context.Background(), "CVE-2025-0001")
	if err != nil {
		t.Fatal(err)
	}
	if result.CVE != "CVE-2025-0001" || len(result.AffectedPackages) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestAuditService_CVEBatchAudit(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/audit/cves" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"result": []map[string]interface{}{
				{"cve": "CVE-2025-0001", "affectedPackages": []interface{}{}, "affectedCpe": []interface{}{}},
				{"cve": "CVE-2025-0002", "affectedPackages": []interface{}{}, "affectedCpe": []interface{}{}},
			},
		}); err != nil {
			t.Fatal(err)
		}
	})

	result, err := client.Audit().CVEBatchAudit(
		context.Background(),
		[]string{"CVE-2025-0001", "CVE-2025-0002"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 || result[1].CVE != "CVE-2025-0002" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestAuditService_ModernAuditValidation(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	tests := []struct {
		name string
		call func() error
	}{
		{"linux version", func() error {
			_, err := client.Audit().LinuxAuditV4(context.Background(), "ubuntu", "", []string{"openssl"})
			return err
		}},
		{"linux packages", func() error {
			_, err := client.Audit().LinuxAuditV4(context.Background(), "ubuntu", "24.04", nil)
			return err
		}},
		{"library packages", func() error {
			_, err := client.Audit().LibraryAudit(context.Background(), nil)
			return err
		}},
		{"cve", func() error {
			_, err := client.Audit().CVEAudit(context.Background(), "")
			return err
		}},
		{"batch cves", func() error {
			_, err := client.Audit().CVEBatchAudit(context.Background(), nil)
			return err
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("expected ErrInvalidInput, got %v", err)
			}
		})
	}
}
