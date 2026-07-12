// Example: Using VScanner for vulnerability scanning.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/kidoz/go-vulners/vscanner"
)

func main() {
	// Get API key from environment
	apiKey := os.Getenv("VULNERS_API_KEY")
	if apiKey == "" {
		log.Fatal("VULNERS_API_KEY environment variable is required")
	}

	// Create VScanner client
	client, err := vscanner.NewClient(apiKey,
		vscanner.WithTimeout(60*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Example 1: List available licenses
	fmt.Println("=== VScanner Licenses ===")
	licenses, err := client.GetLicenses(ctx)
	if err != nil {
		log.Printf("Error getting licenses: %v\n", err)
	} else {
		fmt.Printf("Found %d licenses:\n", len(licenses))
		for _, lic := range licenses {
			fmt.Printf("  - ID: %s, Type: %s\n", lic.ID, lic.Type)
		}
	}

	// Example 2: List projects
	fmt.Println("\n=== VScanner Projects ===")
	projects, err := client.Project().List(ctx,
		vscanner.WithListLimit(10),
	)
	if err != nil {
		log.Printf("Error listing projects: %v\n", err)
	} else {
		fmt.Printf("Found %d projects:\n", len(projects))
		for _, p := range projects {
			fmt.Printf("  - %s: %s (License: %s)\n", p.ID, p.Name, p.LicenseID)
		}

		// If we have projects, show tasks and results for the first one.
		if len(projects) > 0 {
			showProjectDetails(ctx, client, projects[0].ID)
		}
	}

	fmt.Println("\nDone!")
}

func showProjectDetails(ctx context.Context, client *vscanner.Client, projectID string) {
	fmt.Printf("\n=== Tasks for Project %s ===\n", projectID)

	tasks, err := client.Task().List(ctx, projectID)
	if err != nil {
		log.Printf("Error listing tasks: %v\n", err)
		return
	}

	fmt.Printf("Found %d tasks:\n", len(tasks))
	for i := range tasks {
		fmt.Printf("  - %s: %s (Enabled: %t, Schedule: %q)\n",
			tasks[i].ID, tasks[i].Name, tasks[i].Enabled, tasks[i].Schedule)
	}

	// Show results.
	fmt.Printf("\n=== Results for Project %s ===\n", projectID)
	results, err := client.Result().List(ctx, projectID,
		vscanner.WithResultLimit(5),
	)
	if err != nil {
		log.Printf("Error listing results: %v\n", err)
		return
	}

	fmt.Printf("Found %d results:\n", len(results))
	for i := range results {
		fmt.Printf("  - %s (%d screenshots)\n", results[i].ID, len(results[i].Screens))
	}

	// Project-level statistics.
	fmt.Printf("\n=== Statistics for Project %s ===\n", projectID)
	stats, err := client.Project().GetStatistics(ctx, projectID,
		vscanner.StatTotalHosts,
		vscanner.StatVulnerableHosts,
		vscanner.StatUniqueCVE,
	)
	if err != nil {
		log.Printf("Error getting statistics: %v\n", err)
		return
	}
	for name, value := range stats {
		fmt.Printf("  - %s: %s\n", name, value)
	}
}
