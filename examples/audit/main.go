// Example: Auditing software for vulnerabilities using the Vulners API.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/kidoz/go-vulners"
)

func main() {
	// Get API key from environment
	apiKey := os.Getenv("VULNERS_API_KEY")
	if apiKey == "" {
		log.Fatal("VULNERS_API_KEY environment variable is required")
	}

	// Create client
	client, err := vulners.NewClient(apiKey,
		vulners.WithTimeout(60*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Example 1: Audit Linux packages
	fmt.Println("=== Linux Package Audit (Ubuntu 22.04) ===")
	packages := []string{
		"openssl 1.1.1f-1ubuntu2",
		"nginx 1.18.0-0ubuntu1",
		"openssh-server 8.2p1-4ubuntu0.1",
		"curl 7.68.0-1ubuntu2",
	}

	linuxResult, err := client.Audit().LinuxAudit(ctx, "Ubuntu", "22.04", packages)
	if err != nil {
		log.Printf("Linux audit error: %v\n", err)
	} else {
		printAuditResult("Linux Audit", linuxResult)
	}

	// Example 2: Audit software items
	fmt.Println("\n=== Software Audit ===")
	software := []vulners.AuditItem{
		{Software: "nginx", Version: "1.18.0", Type: "software"},
		{Software: "apache", Version: "2.4.41", Type: "software"},
		{Software: "mysql", Version: "8.0.23", Type: "software"},
	}

	softwareResult, err := client.Audit().Software(ctx, software)
	if err != nil {
		log.Printf("Software audit error: %v\n", err)
	} else {
		printSoftwareAuditResult("Software Audit", softwareResult)
	}

	// Example 3: Windows KB audit
	fmt.Println("\n=== Windows KB Audit ===")
	kbList := []string{
		"KB5001330",
		"KB5001337",
		"KB4601319",
	}

	kbResult, err := client.Audit().KBAudit(ctx, "Microsoft Windows 10", kbList)
	if err != nil {
		log.Printf("KB audit error: %v\n", err)
	} else {
		printAuditResult("Windows KB Audit", kbResult)
	}

	fmt.Println("\nDone!")
}

func printAuditResult(name string, result *vulners.AuditResult) {
	fmt.Printf("\n%s Results:\n", name)
	fmt.Printf("  Total CVEs: %d\n", len(result.CVEList))
	fmt.Printf("  CVSS Score: %.1f\n", result.CVSSScore)
	fmt.Printf("  Vulnerabilities: %d\n", len(result.Vulnerabilities))

	if len(result.Vulnerabilities) > 0 {
		fmt.Println("  Top vulnerabilities:")
		count := 5
		if len(result.Vulnerabilities) < count {
			count = len(result.Vulnerabilities)
		}
		for i := 0; i < count; i++ {
			v := result.Vulnerabilities[i]
			cvss := 0.0
			if v.CVSS != nil {
				cvss = v.CVSS.Score
			}
			fmt.Printf("    - %s: %s (CVSS: %.1f)\n", v.Package, v.BulletinID, cvss)
		}
	}

	if result.CumulativeFix != "" {
		fmt.Printf("  Cumulative fix: %s\n", result.CumulativeFix)
	}
}

func printSoftwareAuditResult(name string, result *vulners.SoftwareAuditResult) {
	fmt.Printf("\n%s Results:\n", name)
	fmt.Printf("  Items: %d\n", len(result.Items))

	for _, item := range result.Items {
		if item.MatchedCriteria != "" {
			fmt.Printf("  Matched: %s\n", item.MatchedCriteria)
		}
		fmt.Printf("  Vulnerabilities: %d\n", len(item.Vulnerabilities))
		count := 5
		if len(item.Vulnerabilities) < count {
			count = len(item.Vulnerabilities)
		}
		for i := 0; i < count; i++ {
			v := item.Vulnerabilities[i]
			cvss := 0.0
			if v.CVSS != nil {
				cvss = v.CVSS.Score
			}
			fmt.Printf("    - %s: %s (CVSS: %.1f)\n", v.ID, v.Title, cvss)
		}
	}
}
