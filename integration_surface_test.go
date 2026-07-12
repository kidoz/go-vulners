//go:build integration

package vulners

import (
	"context"
	"testing"
	"time"
)

func TestIntegration_SearchExtendedSurface(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := client.Search().SearchBulletinsAll(ctx, "id:CVE-2021-44228", WithLimit(1)); err != nil {
		t.Fatalf("SearchBulletinsAll failed: %v", err)
	}
	if _, err := client.Search().SearchExploitsAll(ctx, "log4j", WithLimit(1)); err != nil {
		t.Fatalf("SearchExploitsAll failed: %v", err)
	}
	if _, err := client.Search().GetMultipleBulletinsWithReferences(ctx, []string{"CVE-2021-44228"}); err != nil {
		t.Fatalf("GetMultipleBulletinsWithReferences failed: %v", err)
	}
	if _, err := client.Search().GetBulletinReferences(ctx, "CVE-2021-44228"); err != nil {
		t.Fatalf("GetBulletinReferences failed: %v", err)
	}
	if _, err := client.Search().GetKBSeeds(ctx, "MSKB-5000001"); err != nil && err != ErrNotFound {
		t.Fatalf("GetKBSeeds failed: %v", err)
	}
	if _, err := client.Search().GetKBUpdates(ctx, "KB5000001", WithLimit(1)); err != nil {
		t.Fatalf("GetKBUpdates failed: %v", err)
	}
	if _, err := client.Search().GetWebVulnerabilities(ctx, []string{"/wp-login.php"}, nil); err != nil {
		t.Fatalf("GetWebVulnerabilities failed: %v", err)
	}
}

func TestIntegration_AuditExtendedSurface(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	packages := []string{"openssl 3.0.2-0ubuntu1"}
	if result, err := client.Audit().LinuxAuditV4(ctx, "ubuntu", "22.04", packages); err != nil {
		t.Fatalf("LinuxAuditV4 failed: %v", err)
	} else if result.TotalPackages == 0 {
		t.Error("LinuxAuditV4 returned zero total packages")
	}
	if result, err := client.Audit().LibraryAudit(ctx, []string{"pkg:npm/lodash@4.17.21"}); err != nil {
		t.Fatalf("LibraryAudit failed: %v", err)
	} else if result.TotalPackages == 0 {
		t.Error("LibraryAudit returned zero total packages")
	}
	if result, err := client.Audit().CVEAudit(ctx, "CVE-2021-44228"); err != nil {
		t.Fatalf("CVEAudit failed: %v", err)
	} else if result.CVE == "" {
		t.Error("CVEAudit returned an empty CVE")
	}
	if result, err := client.Audit().CVEBatchAudit(ctx, []string{"CVE-2021-44228", "CVE-2021-45046"}); err != nil {
		t.Fatalf("CVEBatchAudit failed: %v", err)
	} else if len(result) != 2 {
		t.Errorf("CVEBatchAudit returned %d results, want 2", len(result))
	}
	if _, err := client.Audit().Host(ctx, "ubuntu", "22.04", []AuditItem{{Part: "a", Product: "openssl", Version: "3.0.2"}}); err != nil {
		t.Fatalf("Host failed: %v", err)
	}
	if _, err := client.Audit().KBAudit(ctx, "Windows 10", []string{"KB5000001"}); err != nil {
		t.Fatalf("KBAudit failed: %v", err)
	}
	if _, err := client.Audit().WinAudit(
		ctx,
		"Windows Server 2012 R2",
		"6.3.9600",
		[]string{"KB5009586", "KB5009624"},
		[]WinAuditItem{{Software: "Microsoft Edge", Version: "107.0.1418.56"}},
	); err != nil {
		t.Fatalf("WinAudit failed: %v", err)
	}
}

func TestIntegration_MiscExtendedSurface(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := client.Misc().GetSuggestion(ctx, "type"); err != nil {
		t.Fatalf("GetSuggestion failed: %v", err)
	}
	if _, err := client.Misc().SearchCPE(ctx, "chrome", "", WithCPESize(0)); err != nil {
		t.Fatalf("SearchCPE with optional vendor and size=0 failed: %v", err)
	}
}

func TestIntegration_ReportSurface(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := client.Report().VulnsSummaryReport(ctx, WithReportLimit(1)); err != nil {
		t.Errorf("VulnsSummaryReport failed: %v", err)
	}
	if _, err := client.Report().VulnsList(ctx, WithReportLimit(1)); err != nil {
		t.Errorf("VulnsList failed: %v", err)
	}
	if _, err := client.Report().IPSummaryReport(ctx, WithReportLimit(1)); err != nil {
		t.Errorf("IPSummaryReport failed: %v", err)
	}
	if _, err := client.Report().ScanList(ctx, WithReportLimit(1)); err != nil {
		t.Errorf("ScanList failed: %v", err)
	}
	if _, err := client.Report().HostVulns(ctx, WithReportLimit(1)); err != nil {
		t.Errorf("HostVulns failed: %v", err)
	}
}

func TestIntegration_AccountReadOnlySurface(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := client.Subscription().List(ctx); err != nil {
		t.Errorf("Subscription.List failed: %v", err)
	}
	if _, err := client.Webhook().List(ctx); err != nil {
		t.Logf("Webhook.List not authorized for this API key: %v", err)
	}
}

func TestIntegration_ArchiveUpdate(t *testing.T) {
	client := getTestClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := client.Archive().FetchCollectionUpdate(ctx, CollectionCVE, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("FetchCollectionUpdate failed: %v", err)
	}
}
