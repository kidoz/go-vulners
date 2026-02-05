//go:build integration

package vulners

import (
	"context"
	"os"
	"testing"
	"time"
)

// Run integration tests with:
//   VULNERS_API_KEY=your-api-key go test -tags=integration -v ./...

func getTestClient(t *testing.T) *Client {
	t.Helper()

	apiKey := os.Getenv("VULNERS_API_KEY")
	if apiKey == "" {
		t.Skip("VULNERS_API_KEY environment variable not set")
	}

	client, err := NewClient(apiKey,
		WithTimeout(60*time.Second),
		WithRetries(3),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	return client
}

func TestIntegration_SearchBulletins(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results, err := client.Search().SearchBulletins(ctx, "CVE-2021-44228", WithLimit(5))
	if err != nil {
		t.Fatalf("SearchBulletins failed: %v", err)
	}

	if results.Total == 0 {
		t.Error("expected at least one result for CVE-2021-44228 (Log4Shell)")
	}

	t.Logf("Found %d total results, retrieved %d bulletins", results.Total, len(results.Bulletins))

	for _, b := range results.Bulletins {
		t.Logf("  - %s: %s (type: %s)", b.ID, b.Title, b.Type)
	}
}

func TestIntegration_GetBulletin(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bulletin, err := client.Search().GetBulletin(ctx, "CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetBulletin failed: %v", err)
	}

	if bulletin.ID != "CVE-2021-44228" {
		t.Errorf("expected ID=CVE-2021-44228, got %s", bulletin.ID)
	}

	t.Logf("Bulletin: %s - %s", bulletin.ID, bulletin.Title)
	t.Logf("  Type: %s, Family: %s", bulletin.Type, bulletin.BulletinFamily)
	if bulletin.CVSS.Score > 0 {
		t.Logf("  CVSS Score: %.1f", bulletin.CVSS.Score)
	}
}

func TestIntegration_GetMultipleBulletins(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ids := []string{"CVE-2021-44228", "CVE-2021-45046"}
	bulletins, err := client.Search().GetMultipleBulletins(ctx, ids)
	if err != nil {
		t.Fatalf("GetMultipleBulletins failed: %v", err)
	}

	if len(bulletins) != 2 {
		t.Errorf("expected 2 bulletins, got %d", len(bulletins))
	}

	for id, b := range bulletins {
		t.Logf("  - %s: %s", id, b.Title)
	}
}

func TestIntegration_SearchExploits(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results, err := client.Search().SearchExploits(ctx, "log4j", WithLimit(5))
	if err != nil {
		t.Fatalf("SearchExploits failed: %v", err)
	}

	t.Logf("Found %d exploit results for 'log4j'", results.Total)

	for _, b := range results.Bulletins {
		t.Logf("  - %s: %s (family: %s)", b.ID, b.Title, b.BulletinFamily)
	}
}

func TestIntegration_LinuxAudit(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test with package format from OpenAPI examples: "name-version-release.arch" or "name version arch"
	packages := []string{"glibc-common-2.17-157.el7_3.5.x86_64"}
	result, err := client.Audit().LinuxAudit(ctx, "centos", "7", packages)
	if err != nil {
		t.Fatalf("LinuxAudit failed: %v", err)
	}

	t.Logf("Audit result: %d CVEs found, CVSS score: %.1f", len(result.CVEList), result.CVSSScore)
	if result.CumulativeFix != "" {
		t.Logf("Cumulative fix: %s", result.CumulativeFix)
	}

	if len(result.CVEList) > 0 {
		t.Logf("CVEs: %v", result.CVEList[:min(5, len(result.CVEList))])
	}
}

func TestIntegration_SearchCPE(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// SearchCPE requires both product and vendor per the API spec
	result, err := client.Misc().SearchCPE(ctx, "chrome", "google", WithCPESize(5))
	if err != nil {
		t.Fatalf("SearchCPE failed: %v", err)
	}

	t.Logf("Best match: %s", result.BestMatch)
	t.Logf("Found %d CPE entries", len(result.CPEs))
	for i, cpe := range result.CPEs {
		if i >= 5 {
			break
		}
		t.Logf("  - %s", cpe)
	}
}

func TestIntegration_GetAIScore(t *testing.T) {
	t.Skip("AI Score endpoint not available in the current API")
	// The /api/v3/ai/scoretext/ endpoint is not documented in the OpenAPI spec
}

func TestIntegration_QueryAutocomplete(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	suggestions, err := client.Misc().QueryAutocomplete(ctx, "log4")
	if err != nil {
		t.Fatalf("QueryAutocomplete failed: %v", err)
	}

	t.Logf("Autocomplete suggestions for 'log4': %d results", len(suggestions))
	for i, s := range suggestions {
		if i >= 5 {
			break
		}
		t.Logf("  - %s", s)
	}
}

func TestIntegration_ContextCancellation(t *testing.T) {
	client := getTestClient(t)

	// Create an already-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.Search().SearchBulletins(ctx, "test")
	if err == nil {
		t.Error("expected error for cancelled context")
	}

	if err != context.Canceled {
		t.Logf("Got expected error type: %v", err)
	}
}

func TestIntegration_NotFound(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.Search().GetBulletin(ctx, "NONEXISTENT-CVE-9999999")
	if err == nil {
		t.Error("expected error for non-existent bulletin")
	}

	if err != ErrNotFound {
		t.Logf("Got error (may be ErrNotFound): %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
