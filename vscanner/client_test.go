package vscanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		apiKey  string
		opts    []Option
		wantErr bool
	}{
		{
			name:    "valid API key",
			apiKey:  "test-api-key",
			wantErr: false,
		},
		{
			name:    "empty API key",
			apiKey:  "",
			wantErr: true,
		},
		{
			name:   "with options",
			apiKey: "test-api-key",
			opts: []Option{
				WithTimeout(60 * time.Second),
				WithRetries(5),
				WithUserAgent("test-agent"),
			},
			wantErr: false,
		},
		{
			name:   "HTTP URL rejected without AllowInsecure",
			apiKey: "test-api-key",
			opts: []Option{
				WithBaseURL("http://vulners.example.com"),
			},
			wantErr: true,
		},
		{
			name:   "HTTP URL allowed with AllowInsecure",
			apiKey: "test-api-key",
			opts: []Option{
				WithBaseURL("http://vulners.example.com"),
				WithAllowInsecure(),
			},
			wantErr: false,
		},
		{
			name:   "localhost HTTP allowed without AllowInsecure",
			apiKey: "test-api-key",
			opts: []Option{
				WithBaseURL("http://localhost:8080"),
			},
			wantErr: false,
		},
		{
			name:   "with custom rate limit",
			apiKey: "test-api-key",
			opts: []Option{
				WithRateLimit(10.0, 20),
			},
			wantErr: false,
		},
		{
			name:   "with proxy URL",
			apiKey: "test-api-key",
			opts: []Option{
				WithProxy("http://proxy.example.com:8080"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.apiKey, tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewClient() returned nil client")
			}
		})
	}
}

// Helper to create a test client with a mock server
func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client, err := NewClient("test-key",
		WithBaseURL(server.URL),
		WithAllowInsecure(),
		WithRateLimit(100, 100),
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// apiResponse is the common wrapper for API responses
type apiResponse struct {
	Result string          `json:"result"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// Helper to create a JSON response handler
func jsonHandler(t *testing.T, data interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := apiResponse{
			Result: "OK",
		}
		if data != nil {
			dataBytes, err := json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			resp.Data = dataBytes
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatal(err)
		}
	}
}

func TestClient_GetLicenses(t *testing.T) {
	data := []License{
		{ID: "license-1", Type: "professional", Hosts: 100},
		{ID: "license-2", Type: "enterprise", Hosts: 1000},
	}

	client := newTestClient(t, jsonHandler(t, data))

	licenses, err := client.GetLicenses(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(licenses) != 2 {
		t.Errorf("expected 2 licenses, got %d", len(licenses))
	}

	if licenses[0].ID != "license-1" {
		t.Errorf("expected ID=license-1, got %s", licenses[0].ID)
	}

	if licenses[0].Hosts != 100 {
		t.Errorf("expected Hosts=100, got %d", licenses[0].Hosts)
	}
}

func TestClient_Services(t *testing.T) {
	client, err := NewClient("test-key")
	if err != nil {
		t.Fatal(err)
	}

	// Test that services are initialized correctly
	project := client.Project()
	if project == nil {
		t.Error("Project() returned nil")
	}

	// Call again to verify sync.Once behavior
	project2 := client.Project()
	if project != project2 {
		t.Error("Project() returned different instances")
	}

	task := client.Task()
	if task == nil {
		t.Error("Task() returned nil")
	}

	result := client.Result()
	if result == nil {
		t.Error("Result() returned nil")
	}
}

func TestProjectService_List(t *testing.T) {
	data := map[string]interface{}{
		"projects": []Project{
			{ID: "proj-1", Name: "Project 1"},
			{ID: "proj-2", Name: "Project 2"},
		},
		"total": 2,
	}

	client := newTestClient(t, jsonHandler(t, data))

	projects, err := client.Project().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(projects) != 2 {
		t.Errorf("expected 2 projects, got %d", len(projects))
	}

	if projects[0].ID != "proj-1" {
		t.Errorf("expected ID=proj-1, got %s", projects[0].ID)
	}
}

func TestProjectService_Get(t *testing.T) {
	data := Project{
		ID:          "proj-1",
		Name:        "Test Project",
		Description: "A test project",
		TaskCount:   5,
		HostCount:   100,
		VulnCount:   50,
	}

	client := newTestClient(t, jsonHandler(t, data))

	project, err := client.Project().Get(context.Background(), "proj-1")
	if err != nil {
		t.Fatal(err)
	}

	if project.ID != "proj-1" {
		t.Errorf("expected ID=proj-1, got %s", project.ID)
	}

	if project.TaskCount != 5 {
		t.Errorf("expected TaskCount=5, got %d", project.TaskCount)
	}
}

func TestProjectService_Create(t *testing.T) {
	data := Project{
		ID:   "new-proj",
		Name: "New Project",
	}

	client := newTestClient(t, jsonHandler(t, data))

	req := &ProjectRequest{Name: "New Project", Description: "A new project"}
	project, err := client.Project().Create(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	if project.ID != "new-proj" {
		t.Errorf("expected ID=new-proj, got %s", project.ID)
	}
}

func TestProjectService_CreateNilRequest(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	_, err := client.Project().Create(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil request")
	}
}

func TestProjectService_Update(t *testing.T) {
	data := Project{
		ID:   "proj-1",
		Name: "Updated Project",
	}

	client := newTestClient(t, jsonHandler(t, data))

	req := &ProjectRequest{Name: "Updated Project"}
	project, err := client.Project().Update(context.Background(), "proj-1", req)
	if err != nil {
		t.Fatal(err)
	}

	if project.Name != "Updated Project" {
		t.Errorf("expected Name='Updated Project', got %s", project.Name)
	}
}

func TestProjectService_Delete(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	err := client.Project().Delete(context.Background(), "proj-1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestTaskService_List(t *testing.T) {
	data := map[string]interface{}{
		"tasks": []Task{
			{ID: "task-1", Name: "Task 1", Status: "completed"},
			{ID: "task-2", Name: "Task 2", Status: "pending"},
		},
		"total": 2,
	}

	client := newTestClient(t, jsonHandler(t, data))

	tasks, err := client.Task().List(context.Background(), "proj-1")
	if err != nil {
		t.Fatal(err)
	}

	if len(tasks) != 2 {
		t.Errorf("expected 2 tasks, got %d", len(tasks))
	}

	if tasks[0].Status != "completed" {
		t.Errorf("expected Status=completed, got %s", tasks[0].Status)
	}
}

func TestTaskService_Get(t *testing.T) {
	data := Task{
		ID:          "task-1",
		ProjectID:   "proj-1",
		Name:        "Test Task",
		Status:      "running",
		Description: "A test task",
	}

	client := newTestClient(t, jsonHandler(t, data))

	task, err := client.Task().Get(context.Background(), "proj-1", "task-1")
	if err != nil {
		t.Fatal(err)
	}

	if task.Status != "running" {
		t.Errorf("expected Status=running, got %s", task.Status)
	}
}

func TestTaskService_Create(t *testing.T) {
	data := Task{
		ID:   "new-task",
		Name: "New Task",
	}

	client := newTestClient(t, jsonHandler(t, data))

	req := &TaskRequest{Name: "New Task", Targets: []string{"192.168.1.0/24"}}
	task, err := client.Task().Create(context.Background(), "proj-1", req)
	if err != nil {
		t.Fatal(err)
	}

	if task.ID != "new-task" {
		t.Errorf("expected ID=new-task, got %s", task.ID)
	}
}

func TestTaskService_Start(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	err := client.Task().Start(context.Background(), "proj-1", "task-1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestTaskService_Stop(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	err := client.Task().Stop(context.Background(), "proj-1", "task-1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestTaskService_Delete(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	err := client.Task().Delete(context.Background(), "proj-1", "task-1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestResultService_List(t *testing.T) {
	data := map[string]interface{}{
		"results": []Result{
			{ID: "result-1", TaskName: "Scan 1", Status: "completed"},
		},
		"total": 1,
	}

	client := newTestClient(t, jsonHandler(t, data))

	results, err := client.Result().List(context.Background(), "proj-1")
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}

	if results[0].Status != "completed" {
		t.Errorf("expected Status=completed, got %s", results[0].Status)
	}
}

func TestResultService_Get(t *testing.T) {
	data := Result{
		ID:        "result-1",
		ProjectID: "proj-1",
		TaskID:    "task-1",
		Status:    "completed",
		HostCount: 50,
		VulnCount: 25,
	}

	client := newTestClient(t, jsonHandler(t, data))

	result, err := client.Result().Get(context.Background(), "proj-1", "result-1")
	if err != nil {
		t.Fatal(err)
	}

	if result.HostCount != 50 {
		t.Errorf("expected HostCount=50, got %d", result.HostCount)
	}

	if result.VulnCount != 25 {
		t.Errorf("expected VulnCount=25, got %d", result.VulnCount)
	}
}

func TestResultService_GetStatistics(t *testing.T) {
	data := Statistics{
		TotalHosts:   100,
		ScannedHosts: 95,
		TotalVulns:   50,
		BySeverity: map[string]int{
			"critical": 5,
			"high":     15,
			"medium":   20,
			"low":      10,
		},
	}

	client := newTestClient(t, jsonHandler(t, data))

	stats, err := client.Result().GetStatistics(context.Background(), "proj-1", "result-1")
	if err != nil {
		t.Fatal(err)
	}

	if stats.TotalHosts != 100 {
		t.Errorf("expected TotalHosts=100, got %d", stats.TotalHosts)
	}

	if stats.BySeverity["critical"] != 5 {
		t.Errorf("expected BySeverity[critical]=5, got %d", stats.BySeverity["critical"])
	}
}

func TestResultService_GetHosts(t *testing.T) {
	data := []HostSummary{
		{Host: "192.168.1.1", VulnCount: 10, Critical: 2, High: 3},
		{Host: "192.168.1.2", VulnCount: 5, Critical: 0, High: 2},
	}

	client := newTestClient(t, jsonHandler(t, data))

	hosts, err := client.Result().GetHosts(context.Background(), "proj-1", "result-1")
	if err != nil {
		t.Fatal(err)
	}

	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}

	if hosts[0].Critical != 2 {
		t.Errorf("expected Critical=2, got %d", hosts[0].Critical)
	}
}

func TestResultService_GetVulnerabilities(t *testing.T) {
	data := []VulnSummary{
		{ID: "vuln-1", Title: "Critical Vuln", Severity: "critical", CVSS: 9.8},
	}

	client := newTestClient(t, jsonHandler(t, data))

	vulns, err := client.Result().GetVulnerabilities(context.Background(), "proj-1", "result-1")
	if err != nil {
		t.Fatal(err)
	}

	if len(vulns) != 1 {
		t.Errorf("expected 1 vuln, got %d", len(vulns))
	}

	if vulns[0].CVSS != 9.8 {
		t.Errorf("expected CVSS=9.8, got %f", vulns[0].CVSS)
	}
}

func TestResultService_Delete(t *testing.T) {
	client := newTestClient(t, jsonHandler(t, nil))

	err := client.Result().Delete(context.Background(), "proj-1", "result-1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestAPIError_Is(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		target     error
		want       bool
	}{
		{"NotFound", 404, ErrNotFound, true},
		{"NotFound mismatch", 500, ErrNotFound, false},
		{"RateLimited", 429, ErrRateLimited, true},
		{"Unauthorized 401", 401, ErrUnauthorized, true},
		{"Unauthorized 403", 403, ErrUnauthorized, true},
		{"BadRequest", 400, ErrBadRequest, true},
		{"ServerError 500", 500, ErrServerError, true},
		{"ServerError 503", 503, ErrServerError, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &APIError{StatusCode: tt.statusCode, Message: "test"}
			if got := err.Is(tt.target); got != tt.want {
				t.Errorf("APIError.Is() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTime_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "RFC3339",
			input:   `"2021-12-09T12:00:00Z"`,
			wantErr: false,
		},
		{
			name:    "RFC3339Nano",
			input:   `"2021-12-09T12:00:00.123456789Z"`,
			wantErr: false,
		},
		{
			name:    "date only",
			input:   `"2021-12-09"`,
			wantErr: false,
		},
		{
			name:    "null",
			input:   `null`,
			wantErr: false,
		},
		{
			name:    "timestamp milliseconds",
			input:   `1639051200000`,
			wantErr: false,
		},
		{
			name:    "datetime without timezone",
			input:   `"2021-12-09T12:00:00"`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tm Time
			err := json.Unmarshal([]byte(tt.input), &tm)
			if (err != nil) != tt.wantErr {
				t.Errorf("Time.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTime_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		time Time
		want string
	}{
		{
			name: "zero time",
			time: Time{},
			want: "null",
		},
		{
			name: "valid time",
			time: Time{Time: time.Date(2021, 12, 9, 12, 0, 0, 0, time.UTC)},
			want: `"2021-12-09T12:00:00Z"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.time)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("Time.MarshalJSON() = %s, want %s", string(got), tt.want)
			}
		})
	}
}

func TestListOptions(t *testing.T) {
	cfg := &listConfig{}

	WithListLimit(50)(cfg)
	if cfg.limit != 50 {
		t.Errorf("expected limit=50, got %d", cfg.limit)
	}

	WithListOffset(10)(cfg)
	if cfg.offset != 10 {
		t.Errorf("expected offset=10, got %d", cfg.offset)
	}

	WithListSort("name", true)(cfg)
	if cfg.sort != "name" {
		t.Errorf("expected sort=name, got %s", cfg.sort)
	}
	if cfg.order != "asc" {
		t.Errorf("expected order=asc, got %s", cfg.order)
	}

	WithListSort("created", false)(cfg)
	if cfg.order != "desc" {
		t.Errorf("expected order=desc, got %s", cfg.order)
	}
}
