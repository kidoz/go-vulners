# go-vulners

A Go client library for the [Vulners](https://vulners.com) vulnerability database API.

[![Version](https://img.shields.io/badge/version-1.1.1-blue)](https://github.com/kidoz/go-vulners/releases/tag/v1.1.1)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/kidoz/go-vulners.svg)](https://pkg.go.dev/github.com/kidoz/go-vulners)
[![Go Report Card](https://goreportcard.com/badge/github.com/kidoz/go-vulners)](https://goreportcard.com/report/github.com/kidoz/go-vulners)

## Features

- Full coverage of Vulners API v3/v4
- Search for vulnerabilities, exploits, and security bulletins
- Audit Linux packages, Windows KBs, software CPEs, and SBOM files
- VScanner integration for vulnerability scanning
- Built-in rate limiting with dynamic adjustment
- Automatic retry with exponential backoff
- Context support for cancellation and timeouts
- Zero external dependencies (standard library only)

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
```

## API Services

### Search Service

```go
// Search bulletins with Lucene query syntax
results, err := client.Search().SearchBulletins(ctx, "CVE-2021-44228",
    vulners.WithLimit(20),
    vulners.WithOffset(0),
    vulners.WithFields("id", "title", "cvss", "published"),
)

// Search for exploits only
exploits, err := client.Search().SearchExploits(ctx, "apache")

// Get bulletin by ID
bulletin, err := client.Search().GetBulletin(ctx, "CVE-2021-44228")

// Get multiple bulletins
bulletins, err := client.Search().GetMultipleBulletins(ctx,
    []string{"CVE-2021-44228", "CVE-2021-45046"},
)

// Get all results with pagination
allBulletins, err := client.Search().SearchBulletinsAll(ctx, "type:cve",
    vulners.WithLimit(1000), // max results
)
```

### Audit Service

```go
// Audit Linux packages
packages := []string{"glibc-common-2.17-157.el7_3.5.x86_64"}
result, err := client.Audit().LinuxAudit(ctx, "centos", "7", packages)
fmt.Printf("Found %d CVEs, max CVSS: %.1f\n", len(result.CVEList), result.CVSSScore)

// Audit Windows KBs
kbList := []string{"KB5009586", "KB5009624"}
result, err := client.Audit().KBAudit(ctx, "Windows Server 2012 R2", kbList)

// Audit software CPEs
software := []vulners.AuditItem{
    {Software: "apache", Version: "2.4.49", Type: "software"},
}
result, err := client.Audit().Software(ctx, software)

// Audit an SBOM file (SPDX or CycloneDX JSON)
f, err := os.Open("sbom.spdx.json")
if err != nil {
    log.Fatal(err)
}
defer f.Close()
sbomResult, err := client.Audit().SBOMAudit(ctx, f)
fmt.Printf("Analyzed %d packages\n", len(sbomResult.Packages))
```

### Archive Service

```go
// Fetch entire collection
bulletins, err := client.Archive().FetchCollection(ctx, vulners.CollectionCVE)

// Fetch updates since timestamp
since := time.Now().Add(-24 * time.Hour)
updates, err := client.Archive().FetchCollectionUpdate(ctx, vulners.CollectionCVE, since)
```

### Other Services

```go
// Webhooks
webhooks, err := client.Webhook().List(ctx)
webhook, err := client.Webhook().Add(ctx, "type:cve AND cvss.score:[9 TO 10]")

// Subscriptions
subs, err := client.Subscription().List(ctx)

// STIX bundles
bundle, err := client.Stix().MakeBundleByID(ctx, "CVE-2021-44228")

// Reports
summary, err := client.Report().VulnsSummaryReport(ctx)

// Misc
cpes, err := client.Misc().SearchCPE(ctx, "chrome", "google")
suggestions, err := client.Misc().QueryAutocomplete(ctx, "log4")
```

## VScanner Client

For vulnerability scanning, use the separate VScanner client:

```go
import "github.com/kidoz/go-vulners/vscanner"

client, err := vscanner.NewClient("your-api-key")
if err != nil {
    log.Fatal(err)
}

// List projects
projects, err := client.Project().List(ctx)

// Create a project
project, err := client.Project().Create(ctx, &vscanner.ProjectRequest{
    Name:        "My Project",
    Description: "Vulnerability scanning project",
})

// Create and run a task
task, err := client.Task().Create(ctx, project.ID, &vscanner.TaskRequest{
    Name:   "Scan Task",
    Hosts:  []string{"192.168.1.0/24"},
    Ports:  "1-1000",
})
err = client.Task().Start(ctx, project.ID, task.ID)

// Get results
results, err := client.Result().List(ctx, project.ID)
```

## Error Handling

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

- [Vulners API Documentation](https://vulners.com/api/v3/apipage/)
- [Vulners Website](https://vulners.com)
