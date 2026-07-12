package vscanner_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/kidoz/go-vulners/vscanner"
)

func ExampleNewClient() {
	// Create a new VScanner client.
	client, err := vscanner.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	_ = client // use client for API calls
}

func ExampleNewClient_withOptions() {
	// Create a client with custom settings.
	client, err := vscanner.NewClient("your-api-key",
		vscanner.WithTimeout(60*time.Second),
		vscanner.WithRetries(5),
		vscanner.WithRateLimit(10.0, 20),
	)
	if err != nil {
		log.Fatal(err)
	}

	_ = client
}

func ExampleProjectService_List() {
	client, err := vscanner.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// List all projects.
	projects, err := client.Project().List(ctx)
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range projects {
		fmt.Printf("Project: %s - %s\n", p.ID, p.Name)
	}
}

func ExampleProjectService_Create() {
	client, err := vscanner.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// A license id is required; fetch one via client.GetLicenses.
	project, err := client.Project().Create(ctx, &vscanner.ProjectRequest{
		Name:         "My Scanning Project",
		LicenseID:    "your-license-id",
		Notification: vscanner.DisabledNotification(),
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Created project: %s\n", project.ID)
}

func ExampleTaskService_Create() {
	client, err := vscanner.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	projectID := "your-project-id"

	// Create a scanning task (schedule is a crontab string).
	task, err := client.Task().Create(ctx, projectID, &vscanner.TaskRequest{
		Name:     "Network Scan",
		Networks: []string{"192.168.1.0/24"},
		Ports:    []string{"1-1000"},
		Schedule: "0 2 * * *",
		Timing:   "normal",
		Enabled:  true,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Created task: %s\n", task.ID)
}

func ExampleTaskService_Start() {
	client, err := vscanner.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Start a scanning task as soon as possible.
	task, err := client.Task().Start(ctx, "your-project-id", "your-task-id")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Task started: %s\n", task.ID)
}

func ExampleResultService_List() {
	client, err := vscanner.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	projectID := "your-project-id"

	// List scan results, filtered and sorted.
	results, err := client.Result().List(ctx, projectID,
		vscanner.WithResultLimit(10),
		vscanner.WithResultSort("last_seen", false),
	)
	if err != nil {
		log.Fatal(err)
	}

	for _, r := range results {
		fmt.Printf("Result %s (%d screenshots)\n", r.ID, len(r.Screens))
	}
}

func ExampleProjectService_GetStatistics() {
	client, err := vscanner.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	projectID := "your-project-id"

	// Get project statistics aggregations.
	stats, err := client.Project().GetStatistics(ctx, projectID,
		vscanner.StatTotalHosts,
		vscanner.StatUniqueCVE,
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("total_hosts: %s\n", stats[vscanner.StatTotalHosts])
}

func Example_workflow() {
	client, err := vscanner.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// 1. Pick a license.
	licenses, err := client.GetLicenses(ctx)
	if err != nil || len(licenses) == 0 {
		log.Fatal("no licenses available")
	}

	// 2. Create a project.
	project, err := client.Project().Create(ctx, &vscanner.ProjectRequest{
		Name:         "Security Assessment",
		LicenseID:    licenses[0].ID,
		Notification: vscanner.DisabledNotification(),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created project: %s\n", project.ID)

	// 3. Create a task.
	task, err := client.Task().Create(ctx, project.ID, &vscanner.TaskRequest{
		Name:     "Initial Scan",
		Networks: []string{"192.168.1.1"},
		Ports:    []string{"22", "80", "443"},
		Schedule: "0 3 * * *",
		Timing:   "normal",
		Enabled:  true,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created task: %s\n", task.ID)

	// 4. Start the task now.
	if _, err := client.Task().Start(ctx, project.ID, task.ID); err != nil {
		log.Fatal(err)
	}

	// 5. Later, fetch results.
	results, err := client.Result().List(ctx, project.ID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Found %d results\n", len(results))
}
