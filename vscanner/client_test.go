package vscanner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
		{name: "valid API key", apiKey: "test-api-key", wantErr: false},
		{name: "empty API key", apiKey: "", wantErr: true},
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
			name:    "HTTP URL rejected without AllowInsecure",
			apiKey:  "test-api-key",
			opts:    []Option{WithBaseURL("http://vulners.example.com")},
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
			name:    "localhost HTTP allowed without AllowInsecure",
			apiKey:  "test-api-key",
			opts:    []Option{WithBaseURL("http://localhost:8080")},
			wantErr: false,
		},
		{
			name:    "with custom rate limit",
			apiKey:  "test-api-key",
			opts:    []Option{WithRateLimit(10.0, 20)},
			wantErr: false,
		},
		{
			name:    "with proxy URL",
			apiKey:  "test-api-key",
			opts:    []Option{WithProxy("http://proxy.example.com:8080")},
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

// capturedRequest records what the mock server received.
type capturedRequest struct {
	method string
	path   string
	query  url.Values
	body   map[string]interface{}
}

// apiResponse is the common envelope for API responses.
type apiResponse struct {
	Result string          `json:"result"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// newTestClient creates a client wired to a mock server.
func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client, err := NewClient("test-key",
		WithBaseURL(server.URL),
		WithAllowInsecure(),
		WithRateLimit(1000, 1000),
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// recordingHandler captures the request and returns data wrapped in the API
// envelope ({"result":"OK","data":...}).
func recordingHandler(t *testing.T, captured *capturedRequest, data interface{}) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.query = r.URL.Query()
		if b, _ := io.ReadAll(r.Body); len(b) > 0 {
			_ = json.Unmarshal(b, &captured.body)
		}
		resp := apiResponse{Result: "OK"}
		if data != nil {
			db, err := json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			resp.Data = db
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatal(err)
		}
	}
}

func assertReq(t *testing.T, c *capturedRequest, method, path string) {
	t.Helper()
	if c.method != method {
		t.Errorf("method = %s, want %s", c.method, method)
	}
	if c.path != path {
		t.Errorf("path = %s, want %s", c.path, path)
	}
}

func TestClient_GetLicenses(t *testing.T) {
	var cap capturedRequest
	data := map[string]interface{}{
		"licenseList": []License{
			{ID: "license-1", Type: "professional"},
			{ID: "license-2", Type: "enterprise"},
		},
	}
	client := newTestClient(t, recordingHandler(t, &cap, data))

	licenses, err := client.GetLicenses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertReq(t, &cap, http.MethodGet, "/api/v3/useraction/licenseids")
	if len(licenses) != 2 {
		t.Fatalf("expected 2 licenses, got %d", len(licenses))
	}
	if licenses[0].ID != "license-1" || licenses[1].Type != "enterprise" {
		t.Errorf("unexpected licenses: %+v", licenses)
	}
}

func TestClient_Services(t *testing.T) {
	client, err := NewClient("test-key")
	if err != nil {
		t.Fatal(err)
	}
	if client.Project() == nil || client.Task() == nil || client.Result() == nil {
		t.Fatal("a service returned nil")
	}
	// Verify sync.Once caching returns the same instance.
	if p1, p2 := client.Project(), client.Project(); p1 != p2 {
		t.Error("Project() returned different instances")
	}
}

func TestProjectService_List(t *testing.T) {
	var cap capturedRequest
	// The API returns a bare array of projects under "data".
	data := []Project{
		{ID: "proj-1", Name: "Project 1", LicenseID: "lic-1"},
		{ID: "proj-2", Name: "Project 2"},
	}
	client := newTestClient(t, recordingHandler(t, &cap, data))

	projects, err := client.Project().List(context.Background(), WithListLimit(10), WithListOffset(5))
	if err != nil {
		t.Fatal(err)
	}
	assertReq(t, &cap, http.MethodGet, "/api/v3/proxy/vscanner/v2/projects/")
	if cap.query.Get("limit") != "10" || cap.query.Get("offset") != "5" {
		t.Errorf("unexpected query: %v", cap.query)
	}
	if len(projects) != 2 || projects[0].ID != "proj-1" {
		t.Errorf("unexpected projects: %+v", projects)
	}
}

func TestProjectService_Create(t *testing.T) {
	var cap capturedRequest
	client := newTestClient(t, recordingHandler(t, &cap, Project{ID: "new-proj", Name: "New Project"}))

	req := &ProjectRequest{
		Name:         "New Project",
		LicenseID:    "lic-1",
		Notification: DisabledNotification(),
	}
	project, err := client.Project().Create(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	assertReq(t, &cap, http.MethodPost, "/api/v3/proxy/vscanner/v2/projects/")
	if cap.body["name"] != "New Project" || cap.body["license_id"] != "lic-1" {
		t.Errorf("unexpected body: %v", cap.body)
	}
	if _, ok := cap.body["notification"]; !ok {
		t.Errorf("notification missing from body: %v", cap.body)
	}
	if project.ID != "new-proj" {
		t.Errorf("expected ID=new-proj, got %s", project.ID)
	}
}

func TestProjectService_CreateNilRequest(t *testing.T) {
	client := newTestClient(t, recordingHandler(t, &capturedRequest{}, nil))
	if _, err := client.Project().Create(context.Background(), nil); err == nil {
		t.Error("expected error for nil request")
	}
}

func TestProjectService_Update(t *testing.T) {
	var cap capturedRequest
	client := newTestClient(t, recordingHandler(t, &cap, Project{ID: "proj-1", Name: "Updated"}))

	req := &ProjectRequest{Name: "Updated", LicenseID: "lic-1", Notification: DisabledNotification()}
	project, err := client.Project().Update(context.Background(), "proj-1", req)
	if err != nil {
		t.Fatal(err)
	}
	assertReq(t, &cap, http.MethodPut, "/api/v3/proxy/vscanner/v2/projects/proj-1")
	if project.Name != "Updated" {
		t.Errorf("expected Name=Updated, got %s", project.Name)
	}
}

func TestProjectService_Delete(t *testing.T) {
	var cap capturedRequest
	client := newTestClient(t, recordingHandler(t, &cap, nil))

	if err := client.Project().Delete(context.Background(), "proj-1"); err != nil {
		t.Fatal(err)
	}
	assertReq(t, &cap, http.MethodDelete, "/api/v3/proxy/vscanner/v2/projects/proj-1")
}

func TestProjectService_GetStatistics(t *testing.T) {
	var cap capturedRequest
	data := map[string]interface{}{"total_hosts": 42}
	client := newTestClient(t, recordingHandler(t, &cap, data))

	stats, err := client.Project().GetStatistics(context.Background(), "proj-1", StatTotalHosts, StatUniqueCVE)
	if err != nil {
		t.Fatal(err)
	}
	assertReq(t, &cap, http.MethodGet, "/api/v3/proxy/vscanner/v2/projects/proj-1/statistic")
	if got := cap.query["stat"]; len(got) != 2 || got[0] != "total_hosts" || got[1] != "unique_cve" {
		t.Errorf("unexpected stat query: %v", got)
	}
	if string(stats["total_hosts"]) != "42" {
		t.Errorf("expected total_hosts=42, got %s", stats["total_hosts"])
	}
}

func TestProjectService_GetStatisticsNoStats(t *testing.T) {
	client := newTestClient(t, recordingHandler(t, &capturedRequest{}, nil))
	if _, err := client.Project().GetStatistics(context.Background(), "proj-1"); err == nil {
		t.Error("expected error when no stats requested")
	}
}

func TestTaskService_List(t *testing.T) {
	var cap capturedRequest
	data := []Task{
		{ID: "task-1", Name: "Task 1", Enabled: true},
		{ID: "task-2", Name: "Task 2"},
	}
	client := newTestClient(t, recordingHandler(t, &cap, data))

	tasks, err := client.Task().List(context.Background(), "proj-1")
	if err != nil {
		t.Fatal(err)
	}
	assertReq(t, &cap, http.MethodGet, "/api/v3/proxy/vscanner/v2/projects/proj-1/tasks")
	if len(tasks) != 2 || tasks[0].Name != "Task 1" {
		t.Errorf("unexpected tasks: %+v", tasks)
	}
}

func TestTaskService_Create(t *testing.T) {
	var cap capturedRequest
	client := newTestClient(t, recordingHandler(t, &cap, Task{ID: "new-task", Name: "New Task"}))

	req := &TaskRequest{
		Name:     "New Task",
		Networks: []string{"192.168.1.0/24"},
		Ports:    []string{"80", "443"},
		Schedule: "0 0 * * *",
		Timing:   "normal",
		Enabled:  true,
	}
	task, err := client.Task().Create(context.Background(), "proj-1", req)
	if err != nil {
		t.Fatal(err)
	}
	assertReq(t, &cap, http.MethodPost, "/api/v3/proxy/vscanner/v2/projects/proj-1/tasks")
	if cap.body["name"] != "New Task" || cap.body["schedule"] != "0 0 * * *" {
		t.Errorf("unexpected body: %v", cap.body)
	}
	if task.ID != "new-task" {
		t.Errorf("expected ID=new-task, got %s", task.ID)
	}
}

func TestTaskService_Update(t *testing.T) {
	var cap capturedRequest
	client := newTestClient(t, recordingHandler(t, &cap, Task{ID: "task-1", Name: "Updated Task"}))

	req := &TaskRequest{Name: "Updated Task", Networks: []string{"10.0.0.0/8"}, Ports: []string{"22"}}
	task, err := client.Task().Update(context.Background(), "proj-1", "task-1", req)
	if err != nil {
		t.Fatal(err)
	}
	assertReq(t, &cap, http.MethodPut, "/api/v3/proxy/vscanner/v2/projects/proj-1/tasks/task-1")
	if task.Name != "Updated Task" {
		t.Errorf("expected Name=Updated Task, got %s", task.Name)
	}
}

func TestTaskService_Start(t *testing.T) {
	var cap capturedRequest
	client := newTestClient(t, recordingHandler(t, &cap, Task{ID: "task-1", Enabled: true}))

	task, err := client.Task().Start(context.Background(), "proj-1", "task-1")
	if err != nil {
		t.Fatal(err)
	}
	assertReq(t, &cap, http.MethodPost, "/api/v3/proxy/vscanner/v2/projects/proj-1/tasks/task-1/start")
	if task.ID != "task-1" {
		t.Errorf("expected ID=task-1, got %s", task.ID)
	}
}

func TestTaskService_Delete(t *testing.T) {
	var cap capturedRequest
	client := newTestClient(t, recordingHandler(t, &cap, nil))

	if err := client.Task().Delete(context.Background(), "proj-1", "task-1"); err != nil {
		t.Fatal(err)
	}
	assertReq(t, &cap, http.MethodDelete, "/api/v3/proxy/vscanner/v2/projects/proj-1/tasks/task-1")
}

func TestResultService_List(t *testing.T) {
	var cap capturedRequest
	data := []Result{
		{ID: "result-1", ProjectID: "proj-1"},
		{ID: "result-2", ProjectID: "proj-1", Screens: map[string]ResultScreen{"443": {Screen: "abc"}}},
	}
	client := newTestClient(t, recordingHandler(t, &cap, data))

	results, err := client.Result().List(context.Background(), "proj-1",
		WithResultSearch("nginx"),
		WithResultCVSSRange(7.0, 10.0),
		WithResultSort("max_cvss", false),
		WithResultLimit(20),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertReq(t, &cap, http.MethodGet, "/api/v3/proxy/vscanner/v2/projects/proj-1/results")
	if cap.query.Get("search") != "nginx" || cap.query.Get("min_cvss") != "7" ||
		cap.query.Get("sort") != "max_cvss" || cap.query.Get("sort_dir") != "desc" ||
		cap.query.Get("limit") != "20" {
		t.Errorf("unexpected query: %v", cap.query)
	}
	if len(results) != 2 || results[1].Screens["443"].Screen != "abc" {
		t.Errorf("unexpected results: %+v", results)
	}
}

func TestResultService_Delete(t *testing.T) {
	var cap capturedRequest
	client := newTestClient(t, recordingHandler(t, &cap, nil))

	if err := client.Result().Delete(context.Background(), "proj-1", "result-1"); err != nil {
		t.Fatal(err)
	}
	assertReq(t, &cap, http.MethodDelete, "/api/v3/proxy/vscanner/v2/projects/proj-1/results/result-1")
}

func TestNotificationHelpers(t *testing.T) {
	d := DisabledNotification()
	if d.Period != "disabled" || d.Email == nil || d.Slack == nil {
		t.Errorf("unexpected DisabledNotification: %+v", d)
	}
	n := NewNotification("daily", []string{"a@b.c"}, nil)
	if n.Period != "daily" || len(n.Email) != 1 || n.Slack == nil {
		t.Errorf("unexpected NewNotification: %+v", n)
	}
}

func TestNestedErrorMessage(t *testing.T) {
	// The API returns errors nested under data.error with an HTTP error status.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"result":"error","data":{"error":"invalid endpoint"}}`))
	}
	client := newTestClient(t, handler)

	_, err := client.Project().List(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 404 {
		t.Errorf("expected status 404, got %d", apiErr.StatusCode)
	}
	if apiErr.Message != "invalid endpoint" {
		t.Errorf("expected message 'invalid endpoint', got %q", apiErr.Message)
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
		{"RFC3339", `"2021-12-09T12:00:00Z"`, false},
		{"RFC3339Nano", `"2021-12-09T12:00:00.123456789Z"`, false},
		{"date only", `"2021-12-09"`, false},
		{"null", `null`, false},
		{"timestamp milliseconds", `1639051200000`, false},
		{"datetime without timezone", `"2021-12-09T12:00:00"`, false},
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
		{"zero time", Time{}, "null"},
		{"valid time", Time{Time: time.Date(2021, 12, 9, 12, 0, 0, 0, time.UTC)}, `"2021-12-09T12:00:00Z"`},
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
	cfg := newListConfig(WithListLimit(50), WithListOffset(10))
	if cfg.limit != 50 {
		t.Errorf("expected limit=50, got %d", cfg.limit)
	}
	if cfg.offset != 10 {
		t.Errorf("expected offset=10, got %d", cfg.offset)
	}
}

// TestMakeCheckRedirect covers the cross-host redirect policy: same-host
// redirects keep the API key, allowlisted CDN hosts are followed with
// sensitive headers stripped, and everything else is blocked.
func TestMakeCheckRedirect(t *testing.T) {
	const apiKey = "secret-key"
	base := "https://vulners.com"

	newReq := func(rawURL string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Api-Key", apiKey)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("Cookie", "session=abc")
		return req
	}

	t.Run("same host keeps sensitive headers", func(t *testing.T) {
		check := makeCheckRedirect(base, []string{"storage.googleapis.com"})
		req := newReq("https://vulners.com/api/v4/resource")
		if err := check(req, []*http.Request{newReq(base)}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := req.Header.Get("X-Api-Key"); got != apiKey {
			t.Errorf("X-Api-Key lost on same-host redirect: %q", got)
		}
	})

	t.Run("allowlisted CDN host strips sensitive headers", func(t *testing.T) {
		check := makeCheckRedirect(base, []string{"storage.googleapis.com"})
		req := newReq("https://storage.googleapis.com/x")
		if err := check(req, []*http.Request{newReq(base)}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := req.Header.Get("X-Api-Key"); got != "" {
			t.Errorf("X-Api-Key leaked to CDN host: %q", got)
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization leaked to CDN host: %q", got)
		}
		if got := req.Header.Get("Cookie"); got != "" {
			t.Errorf("Cookie leaked to CDN host: %q", got)
		}
	})

	t.Run("unknown host is blocked", func(t *testing.T) {
		check := makeCheckRedirect(base, []string{"storage.googleapis.com"})
		req := newReq("https://evil.example.com/steal")
		err := check(req, []*http.Request{newReq(base)})
		if err == nil {
			t.Fatal("expected error for unknown host, got nil")
		}
		if !strings.Contains(err.Error(), "refusing to follow redirect to different host") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("HTTPS to HTTP downgrade is blocked even on allowlisted host", func(t *testing.T) {
		check := makeCheckRedirect(base, []string{"storage.googleapis.com"})
		req := newReq("http://storage.googleapis.com/x")
		err := check(req, []*http.Request{newReq(base)})
		if err == nil {
			t.Fatal("expected error for HTTPS->HTTP downgrade, got nil")
		}
		if !strings.Contains(err.Error(), "refusing to follow redirect from HTTPS to HTTP") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

func TestWithAllowedRedirectHosts(t *testing.T) {
	var cfg clientConfig
	cfg.allowedRedirectHosts = append([]string(nil), defaultAllowedRedirectHosts...)

	WithAllowedRedirectHosts("  CDN.Example.COM  ", "", "extra.test")(&cfg)

	want := []string{"storage.googleapis.com", "cdn.example.com", "extra.test"}
	if len(cfg.allowedRedirectHosts) != len(want) {
		t.Fatalf("expected %d hosts, got %d (%v)", len(want), len(cfg.allowedRedirectHosts), cfg.allowedRedirectHosts)
	}
	for i := range want {
		if cfg.allowedRedirectHosts[i] != want[i] {
			t.Errorf("index %d: want %q, got %q", i, want[i], cfg.allowedRedirectHosts[i])
		}
	}
}
