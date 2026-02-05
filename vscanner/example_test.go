package vscanner_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/kidoz/go-vulners/vscanner"
)

func ExampleNewClient() {
	// Create a new VScanner client
	client, err := vscanner.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	_ = client // use client for API calls
}

func ExampleNewClient_withOptions() {
	// Create a client with custom settings
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

	// List all projects
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

	// Create a new project
	project, err := client.Project().Create(ctx, &vscanner.ProjectRequest{
		Name:        "My Scanning Project",
		Description: "Vulnerability scanning for production systems",
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

	// Create a scanning task
	task, err := client.Task().Create(ctx, projectID, &vscanner.TaskRequest{
		Name:        "Network Scan",
		Description: "Scan internal network",
		Targets:     []string{"192.168.1.0/24"},
		Config: &vscanner.TaskConfig{
			ScanType: "normal",
			Ports:    "1-1000",
		},
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
	projectID := "your-project-id"
	taskID := "your-task-id"

	// Start a scanning task
	err = client.Task().Start(ctx, projectID, taskID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Task started successfully")
}

func ExampleResultService_List() {
	client, err := vscanner.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	projectID := "your-project-id"

	// List scan results
	results, err := client.Result().List(ctx, projectID,
		vscanner.WithListLimit(10),
		vscanner.WithListSort("startedAt", false),
	)
	if err != nil {
		log.Fatal(err)
	}

	for _, r := range results {
		fmt.Printf("Scan %s: %d hosts, %d vulnerabilities\n",
			r.ID, r.HostCount, r.VulnCount)
	}
}

func ExampleResultService_GetStatistics() {
	client, err := vscanner.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	projectID := "your-project-id"
	resultID := "your-result-id"

	// Get scan statistics
	stats, err := client.Result().GetStatistics(ctx, projectID, resultID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Total hosts: %d\n", stats.TotalHosts)
	fmt.Printf("Total vulnerabilities: %d\n", stats.TotalVulns)
	if stats.BySeverity != nil {
		fmt.Printf("Critical: %d\n", stats.BySeverity["critical"])
		fmt.Printf("High: %d\n", stats.BySeverity["high"])
	}
}

func ExampleResultService_GetHosts() {
	client, err := vscanner.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	projectID := "your-project-id"
	resultID := "your-result-id"

	// Get hosts from scan results
	hosts, err := client.Result().GetHosts(ctx, projectID, resultID)
	if err != nil {
		log.Fatal(err)
	}

	for _, h := range hosts {
		fmt.Printf("Host %s: %d vulns (Critical: %d, High: %d)\n",
			h.Host, h.VulnCount, h.Critical, h.High)
	}
}

func Example_workflow() {
	client, err := vscanner.NewClient("your-api-key")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// 1. Create a project
	project, err := client.Project().Create(ctx, &vscanner.ProjectRequest{
		Name: "Security Assessment",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created project: %s\n", project.ID)

	// 2. Create a task
	task, err := client.Task().Create(ctx, project.ID, &vscanner.TaskRequest{
		Name:    "Initial Scan",
		Targets: []string{"192.168.1.1"},
		Config: &vscanner.TaskConfig{
			ScanType: "fast",
			Ports:    "22,80,443",
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created task: %s\n", task.ID)

	// 3. Start the task
	err = client.Task().Start(ctx, project.ID, task.ID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Task started")

	// 4. Wait for results and view them
	// (In practice, you'd poll for task completion)
	results, err := client.Result().List(ctx, project.ID)
	if err != nil {
		log.Fatal(err)
	}

	for _, r := range results {
		fmt.Printf("Result: %d vulnerabilities found\n", r.VulnCount)
	}
}
