package vulners_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/kidoz/go-vulners"
)

func ExampleNewClient() {
	// Create a new client with default settings
	client, err := vulners.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	_ = client // use client for API calls
}

func ExampleNewClient_withOptions() {
	// Create a client with custom settings
	client, err := vulners.NewClient("your-api-key",
		vulners.WithTimeout(60*time.Second),
		vulners.WithRetries(5),
		vulners.WithRateLimit(10.0, 20),
		vulners.WithUserAgent("my-app/1.0"),
	)
	if err != nil {
		log.Fatal(err)
	}

	_ = client
}

func ExampleSearchService_SearchBulletins() {
	client, err := vulners.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	// Search for CVEs related to log4j
	results, err := client.Search().SearchBulletins(ctx, "log4j",
		vulners.WithLimit(10),
		vulners.WithFields("id", "title", "cvss", "published"),
	)
	cancel() // Clean up context
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d results\n", results.Total)
	for _, b := range results.Bulletins {
		fmt.Printf("- %s: %s\n", b.ID, b.Title)
	}
}

func ExampleSearchService_GetBulletin() {
	client, err := vulners.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Get a specific vulnerability by ID
	bulletin, err := client.Search().GetBulletin(ctx, "CVE-2021-44228")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Title: %s\n", bulletin.Title)
	if bulletin.CVSS != nil {
		fmt.Printf("CVSS Score: %.1f\n", bulletin.CVSS.Score)
	}
}

func ExampleSearchService_SearchExploits() {
	client, err := vulners.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Search for exploits only
	results, err := client.Search().SearchExploits(ctx, "apache",
		vulners.WithLimit(5),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d exploits\n", results.Total)
}

func ExampleAuditService_LinuxAudit() {
	client, err := vulners.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Audit installed packages on a Linux system
	packages := []string{
		"openssl-1.1.1f-1ubuntu2",
		"nginx-1.18.0-0ubuntu1",
	}

	result, err := client.Audit().LinuxAudit(ctx, "Ubuntu", "20.04", packages)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d CVEs\n", len(result.CVEList))
	fmt.Printf("Maximum CVSS Score: %.1f\n", result.CVSSScore)
}

func ExampleAuditService_KBAudit() {
	client, err := vulners.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Audit Windows systems by installed KB updates
	kbList := []string{
		"KB5009586",
		"KB5009624",
	}

	result, err := client.Audit().KBAudit(ctx, "Windows Server 2019", kbList)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d vulnerabilities\n", len(result.Vulnerabilities))
}

func ExampleArchiveService_FetchCollection() {
	client, err := vulners.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Fetch the entire CVE collection (use with caution - large dataset)
	bulletins, err := client.Archive().FetchCollection(ctx, vulners.CollectionCVE)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Fetched %d CVE bulletins\n", len(bulletins))
}

func ExampleArchiveService_FetchCollectionUpdate() {
	client, err := vulners.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Fetch CVEs updated in the last 24 hours
	since := time.Now().Add(-24 * time.Hour)
	bulletins, err := client.Archive().FetchCollectionUpdate(ctx, vulners.CollectionCVE, since)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d updated CVEs\n", len(bulletins))
}

func ExampleWebhookService_Add() {
	client, err := vulners.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Create a webhook for critical CVEs
	webhook, err := client.Webhook().Add(ctx, "type:cve AND cvss.score:[9 TO 10]")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Created webhook: %s\n", webhook.ID)
}

func ExampleMiscService_SearchCPE() {
	client, err := vulners.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Search for CPE entries
	result, err := client.Misc().SearchCPE(ctx, "chrome", "google")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Best match: %s\n", result.BestMatch)
	fmt.Printf("Found %d CPEs\n", len(result.CPEs))
}

func ExampleStixService_MakeBundleByID() {
	client, err := vulners.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Generate a STIX bundle for a vulnerability
	bundle, err := client.Stix().MakeBundleByID(ctx, "CVE-2021-44228")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Bundle type: %s\n", bundle.Type)
	fmt.Printf("Bundle ID: %s\n", bundle.ID)
}

func ExampleReportService_VulnsSummaryReport() {
	client, err := vulners.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Get a summary of vulnerabilities
	summary, err := client.Report().VulnsSummaryReport(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Total vulnerabilities: %d\n", summary.Total)
	fmt.Printf("Critical: %d\n", summary.Critical)
	fmt.Printf("High: %d\n", summary.High)
}

func Example_errorHandling() {
	client, err := vulners.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Handle errors appropriately
	_, err = client.Search().GetBulletin(ctx, "NONEXISTENT-CVE")
	if err != nil {
		switch {
		case errors.Is(err, vulners.ErrNotFound):
			fmt.Println("Bulletin not found")
		case errors.Is(err, vulners.ErrRateLimited):
			fmt.Println("Rate limit exceeded, retry later")
		case errors.Is(err, vulners.ErrUnauthorized):
			fmt.Println("Invalid API key")
		default:
			// Check for API errors with status codes
			var apiErr *vulners.APIError
			if errors.As(err, &apiErr) {
				fmt.Printf("API error %d: %s\n", apiErr.StatusCode, apiErr.Message)
			}
		}
	}
}
