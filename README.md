# go-vulners

A Go client library for the [Vulners](https://vulners.com) vulnerability database API.

[![Version](https://img.shields.io/github/v/release/kidoz/go-vulners)](https://github.com/kidoz/go-vulners/releases/latest)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/kidoz/go-vulners.svg)](https://pkg.go.dev/github.com/kidoz/go-vulners)
[![Go Report Card](https://goreportcard.com/badge/github.com/kidoz/go-vulners)](https://goreportcard.com/report/github.com/kidoz/go-vulners)

## Features

- Typed clients for Vulners API v3/v4 search, audit, archive, reporting, alert, and STIX endpoints
- Search for vulnerabilities, exploits, and security bulletins
- Audit Linux packages, Windows KBs, software CPEs, raw software descriptions, and SBOM files
- VScanner integration for vulnerability scanning
- Built-in rate limiting with dynamic adjustment
- Automatic retry with exponential backoff
- Context support for cancellation and timeouts
- No runtime dependencies beyond the Go standard library

## Installation

```bash
go get github.com/kidoz/go-vulners
```

Requires Go 1.21 or later.

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/kidoz/go-vulners"
)

func main() {
    // Create client with API key
    client, err := vulners.NewClient("your-api-key")
    if err != nil {
        log.Fatal(err)
    }

    // Search for vulnerabilities
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    results, err := client.Search().SearchBulletins(ctx, "log4j", vulners.WithLimit(10))
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d results\n", results.Total)
    for _, b := range results.Bulletins {
        fmt.Printf("  - %s: %s\n", b.ID, b.Title)
    }
}
```

## Configuration Options

Inside a function with the imports shown in the Quick Start, configure the client with functional
options:

```go
client, err := vulners.NewClient("your-api-key",
    // Custom timeout (default: 30s)
    vulners.WithTimeout(60*time.Second),

    // Custom retry count (default: 3)
    vulners.WithRetries(5),

    // Custom rate limit (default: 5 req/s, burst 10)
    vulners.WithRateLimit(10.0, 20),

    // Custom User-Agent
    vulners.WithUserAgent("my-app/1.0"),

    // HTTP proxy
    vulners.WithProxy("http://proxy.example.com:8080"),

    // Custom base URL (for testing)
    vulners.WithBaseURL("https://custom.vulners.com"),
)
if err != nil {
    log.Fatal(err)
}
_ = client // Use the configured client to access API services.
```

## API Services

The service examples below are independent function-body fragments. They assume the imports,
initialized `client`, and `ctx` shown in the Quick Start; the SBOM example additionally requires
`os`.

### Search Service

```go
// Search bulletins with Lucene query syntax
results, err := client.Search().SearchBulletins(ctx, "CVE-2021-44228",
    vulners.WithLimit(20),
    vulners.WithOffset(0),
    vulners.WithFields("id", "title", "cvss", "published"),
)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d bulletins\n", results.Total)

// Search for exploits only
exploits, err := client.Search().SearchExploits(ctx, "apache")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d exploits\n", exploits.Total)

// Get all matching exploits with pagination
allExploits, err := client.Search().SearchExploitsAll(ctx, "apache")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Fetched %d exploits\n", len(allExploits))

// Get bulletin by ID
bulletin, err := client.Search().GetBulletin(ctx, "CVE-2021-44228")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Bulletin: %s\n", bulletin.Title)

// Get multiple bulletins
bulletins, err := client.Search().GetMultipleBulletins(ctx,
    []string{"CVE-2021-44228", "CVE-2021-45046"},
)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Fetched %d bulletins\n", len(bulletins))

// Fetch bulletins and their grouped references in one request
withReferences, err := client.Search().GetMultipleBulletinsWithReferences(ctx,
    []string{"CVE-2021-44228", "CVE-2021-45046"},
)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Fetched %d reference groups\n", len(withReferences.References))

// Search vulnerabilities associated with web paths
webVulns, err := client.Search().GetWebVulnerabilities(ctx,
    []string{"/admin", "/login"}, nil,
)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Matched %d paths\n", len(webVulns))

// Get all results with pagination
allBulletins, err := client.Search().SearchBulletinsAll(ctx, "type:cve",
    vulners.WithLimit(1000), // max results
)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Fetched %d bulletins\n", len(allBulletins))
```

### Audit Service

```go
// Audit Linux packages with the modern v4 endpoint
packages := []string{"glibc-common-2.17-157.el7_3.5.x86_64"}
linuxResult, err := client.Audit().LinuxAuditV4(ctx, "centos", "7", packages,
    vulners.WithOSArch("x86_64"),
    vulners.WithIncludeCandidates(true),
)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Analyzed %d packages\n", linuxResult.TotalPackages)

// Audit Windows KBs
kbList := []string{"KB5009586", "KB5009624"}
kbResult, err := client.Audit().KBAudit(ctx, "Windows Server 2012 R2", kbList)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d Windows vulnerabilities\n", len(kbResult.Vulnerabilities))

// Audit software CPEs
software := []vulners.AuditItem{
    {Part: "a", Product: "apache", Version: "2.4.49"},
}
softwareResult, err := client.Audit().Software(ctx, software)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Audited %d software items\n", len(softwareResult.Items))

// Resolve free-form software descriptions and audit the matched CPEs
smartResult, err := client.Audit().SmartAudit(ctx,
    []string{"Adobe Reader 5.3", "OpenSSL 1.0.1"},
    vulners.WithAuditCatalog("official"),
)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Smart Audit resolved %d items\n", len(smartResult.Items))

// Audit libraries using Package URLs (PURLs)
libraryResult, err := client.Audit().LibraryAudit(ctx,
    []string{"pkg:golang/golang.org/x/text@v0.3.0"},
)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Analyzed %d library packages\n", libraryResult.TotalPackages)

// Find package and CPE definitions affected by CVEs
cveResult, err := client.Audit().CVEAudit(ctx, "CVE-2021-44228")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Audited %s\n", cveResult.CVE)
cveResults, err := client.Audit().CVEBatchAudit(ctx,
    []string{"CVE-2021-44228", "CVE-2021-45046"},
)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Audited %d CVEs\n", len(cveResults))

// Audit an SBOM file (SPDX or CycloneDX JSON)
f, err := os.Open("sbom.spdx.json")
if err != nil {
    log.Fatal(err)
}
defer func() { _ = f.Close() }()
sbomResult, err := client.Audit().SBOMAudit(ctx, f)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Analyzed %d packages\n", len(sbomResult.Packages))
```

### Archive Service

```go
// Fetch entire collection
bulletins, err := client.Archive().FetchCollection(ctx, vulners.CollectionCVE)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Fetched %d CVEs\n", len(bulletins))

// Fetch updates since timestamp
since := time.Now().Add(-24 * time.Hour)
updates, err := client.Archive().FetchCollectionUpdate(ctx, vulners.CollectionCVE, since)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Fetched %d CVE updates\n", len(updates))
```

### Other Services

```go
// Webhooks
webhooks, err := client.Webhook().List(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d webhooks\n", len(webhooks))
webhook, err := client.Webhook().Add(ctx, "type:cve AND cvss.score:[9 TO 10]")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Created webhook %s\n", webhook.ID)

// Subscriptions
subs, err := client.Subscription().List(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d subscriptions\n", len(subs))

// STIX bundles
bundle, err := client.Stix().MakeBundleByID(ctx, "CVE-2021-44228")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Created bundle %s\n", bundle.ID)

// Reports
summary, err := client.Report().VulnsSummaryReport(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d vulnerabilities\n", summary.Total)

// Misc
cpes, err := client.Misc().SearchCPE(ctx, "chrome", "google")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d CPEs\n", len(cpes.CPEs))
suggestions, err := client.Misc().QueryAutocomplete(ctx, "log4")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d suggestions\n", len(suggestions))
```

## VScanner Client

For vulnerability scanning, import `github.com/kidoz/go-vulners/vscanner`. The following is a
function-body fragment that assumes an initialized `ctx` and the `fmt` and `log` imports:

```go
client, err := vscanner.NewClient("your-api-key")
if err != nil {
    log.Fatal(err)
}

// Licenses (a license id is required to create a project)
licenses, err := client.GetLicenses(ctx)
if err != nil {
    log.Fatal(err)
}
if len(licenses) == 0 {
    log.Fatal("no VScanner licenses available")
}

// List projects
projects, err := client.Project().List(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d projects\n", len(projects))

// Create a project
project, err := client.Project().Create(ctx, &vscanner.ProjectRequest{
    Name:         "My Project",
    LicenseID:    licenses[0].ID,
    Notification: vscanner.DisabledNotification(),
})
if err != nil {
    log.Fatal(err)
}

// Create and run a task (schedule is a crontab string)
task, err := client.Task().Create(ctx, project.ID, &vscanner.TaskRequest{
    Name:     "Scan Task",
    Networks: []string{"192.168.1.0/24"},
    Ports:    []string{"1-1000"},
    Schedule: "0 2 * * *",
    Timing:   "normal",
    Enabled:  true,
})
if err != nil {
    log.Fatal(err)
}
task, err = client.Task().Start(ctx, project.ID, task.ID)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Started task %s\n", task.ID)

// Get results and project statistics
results, err := client.Result().List(ctx, project.ID)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d results\n", len(results))
stats, err := client.Project().GetStatistics(ctx, project.ID, vscanner.StatTotalHosts)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Total hosts: %s\n", stats[vscanner.StatTotalHosts])
```

## Error Handling

Given an initialized `client` and `ctx`, inspect sentinel and structured API errors with `errors`:

```go
result, err := client.Search().GetBulletin(ctx, "NONEXISTENT-CVE")
if err != nil {
    // Check for specific error types
    if errors.Is(err, vulners.ErrNotFound) {
        fmt.Println("Bulletin not found")
    } else if errors.Is(err, vulners.ErrRateLimited) {
        fmt.Println("Rate limit exceeded, retry later")
    } else if errors.Is(err, vulners.ErrUnauthorized) {
        fmt.Println("Invalid API key")
    } else {
        // Check for API errors with status codes
        var apiErr *vulners.APIError
        if errors.As(err, &apiErr) {
            fmt.Printf("API error %d: %s\n", apiErr.StatusCode, apiErr.Message)
        }
    }
} else {
    fmt.Printf("Bulletin: %s - %s\n", result.ID, result.Title)
}
```

## Rate Limiting

The client includes built-in rate limiting that:

- Defaults to 5 requests/second with burst of 10
- Automatically adjusts based on `X-Vulners-Ratelimit-Reqlimit` response headers
- Supports context cancellation during rate limit waits

## Testing

```bash
# Run unit tests
go test ./...

# Run integration tests (requires API key)
VULNERS_API_KEY=your-key go test -tags=integration -v ./...
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Links

- [Vulners API Documentation](https://docs.vulners.com/docs/api/)
- [Vulners Website](https://vulners.com)
