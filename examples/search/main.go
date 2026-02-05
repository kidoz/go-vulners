// Example: Searching for vulnerabilities using the Vulners API.
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

	// Create client with custom options
	client, err := vulners.NewClient(apiKey,
		vulners.WithTimeout(60*time.Second),
		vulners.WithRetries(3),
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Example 1: Search for a specific CVE
	fmt.Println("=== Searching for CVE-2021-44228 (Log4Shell) ===")
	results, err := client.Search().SearchBulletins(ctx, "CVE-2021-44228",
		vulners.WithLimit(5),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d results:\n", results.Total)
	for _, b := range results.Bulletins {
		fmt.Printf("  - [%s] %s (CVSS: %.1f)\n", b.ID, b.Title, getCVSSScore(b))
	}

	// Example 2: Get a specific bulletin by ID
	fmt.Println("\n=== Getting CVE-2021-44228 details ===")
	bulletin, err := client.Search().GetBulletin(ctx, "CVE-2021-44228")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("ID: %s\n", bulletin.ID)
	fmt.Printf("Title: %s\n", bulletin.Title)
	fmt.Printf("Description: %.200s...\n", bulletin.Description)
	if bulletin.CVSS != nil {
		fmt.Printf("CVSS Score: %.1f\n", bulletin.CVSS.Score)
	}

	// Example 3: Search for exploits
	fmt.Println("\n=== Searching for Log4Shell exploits ===")
	exploits, err := client.Search().SearchExploits(ctx, "log4j",
		vulners.WithLimit(5),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d exploits:\n", exploits.Total)
	for _, e := range exploits.Bulletins {
		fmt.Printf("  - [%s] %s\n", e.ID, e.Title)
	}

	// Example 4: Get multiple bulletins at once
	fmt.Println("\n=== Getting multiple CVEs ===")
	cves := []string{"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"}
	bulletins, err := client.Search().GetMultipleBulletins(ctx, cves)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Retrieved %d bulletins:\n", len(bulletins))
	for id, b := range bulletins {
		fmt.Printf("  - %s: %s\n", id, b.Title)
	}

	fmt.Println("\nDone!")
}

func getCVSSScore(b vulners.Bulletin) float64 {
	if b.CVSS3 != nil {
		return b.CVSS3.Score
	}
	if b.CVSS != nil {
		return b.CVSS.Score
	}
	return 0
}
