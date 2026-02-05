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
			fmt.Printf("  - ID: %s, Type: %s, Hosts: %d\n", lic.ID, lic.Type, lic.Hosts)
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
			fmt.Printf("  - %s: %s (Tasks: %d, Hosts: %d, Vulns: %d)\n",
				p.ID, p.Name, p.TaskCount, p.HostCount, p.VulnCount)
		}

		// If we have projects, show tasks for the first one
		if len(projects) > 0 {
			project := projects[0]
			showProjectDetails(ctx, client, project.ID)
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
		fmt.Printf("  - %s: %s (Status: %s)\n", tasks[i].ID, tasks[i].Name, tasks[i].Status)
	}

	// Show results
	fmt.Printf("\n=== Results for Project %s ===\n", projectID)
	results, err := client.Result().List(ctx, projectID,
		vscanner.WithListLimit(5),
	)
	if err != nil {
		log.Printf("Error listing results: %v\n", err)
		return
	}

	fmt.Printf("Found %d results:\n", len(results))
	for _, r := range results {
		fmt.Printf("  - %s: Task=%s, Status=%s, Hosts=%d, Vulns=%d\n",
			r.ID, r.TaskName, r.Status, r.HostCount, r.VulnCount)

		// Get statistics for completed scans
		if r.Status == "completed" && r.ID != "" {
			stats, err := client.Result().GetStatistics(ctx, projectID, r.ID)
			if err == nil && stats != nil {
				fmt.Printf("    Statistics: Total Hosts=%d, Total Vulns=%d\n",
					stats.TotalHosts, stats.TotalVulns)
				if len(stats.BySeverity) > 0 {
					fmt.Printf("    By Severity: %v\n", stats.BySeverity)
				}
			}
		}
	}
}
