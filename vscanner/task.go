package vscanner

import (
	"context"
	"fmt"
)

// TaskService provides methods for managing VScanner tasks.
type TaskService struct {
	client *Client
}

// Task represents a VScanner task.
type Task struct {
	ID          string      `json:"id,omitempty"`
	ProjectID   string      `json:"projectId,omitempty"`
	Name        string      `json:"name,omitempty"`
	Description string      `json:"description,omitempty"`
	Status      string      `json:"status,omitempty"`
	Type        string      `json:"type,omitempty"`
	Schedule    *Schedule   `json:"schedule,omitempty"`
	Targets     []string    `json:"targets,omitempty"`
	Config      *TaskConfig `json:"config,omitempty"`
	Created     *Time       `json:"created,omitempty"`
	Modified    *Time       `json:"modified,omitempty"`
	LastRun     *Time       `json:"lastRun,omitempty"`
	NextRun     *Time       `json:"nextRun,omitempty"`
}

// Schedule represents a task schedule.
type Schedule struct {
	Enabled    bool   `json:"enabled,omitempty"`
	Type       string `json:"type,omitempty"` // once, daily, weekly, monthly
	Time       string `json:"time,omitempty"` // HH:MM format
	DayOfWeek  int    `json:"dayOfWeek,omitempty"`
	DayOfMonth int    `json:"dayOfMonth,omitempty"`
	StartDate  string `json:"startDate,omitempty"`
}

// TaskConfig represents task configuration options.
type TaskConfig struct {
	ScanType       string   `json:"scanType,omitempty"` // fast, normal, full
	Ports          string   `json:"ports,omitempty"`    // port range or list
	ExcludePorts   string   `json:"excludePorts,omitempty"`
	Credentials    []string `json:"credentials,omitempty"`
	MaxHosts       int      `json:"maxHosts,omitempty"`
	MaxConcurrency int      `json:"maxConcurrency,omitempty"`
	Timeout        int      `json:"timeout,omitempty"`
}

// TaskRequest represents a request to create or update a task.
type TaskRequest struct {
	Name        string      `json:"name,omitempty"`
	Description string      `json:"description,omitempty"`
	Type        string      `json:"type,omitempty"`
	Schedule    *Schedule   `json:"schedule,omitempty"`
	Targets     []string    `json:"targets,omitempty"`
	Config      *TaskConfig `json:"config,omitempty"`
}

// taskListResponse represents the task list response.
type taskListResponse struct {
	Tasks []Task `json:"tasks"`
	Total int    `json:"total,omitempty"`
}

// List returns all tasks for a project.
func (s *TaskService) List(ctx context.Context, projectID string, opts ...ListOption) ([]Task, error) {
	cfg := &listConfig{
		limit: 100,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	params := map[string]string{
		"projectId": projectID,
	}
	if cfg.limit > 0 {
		params["limit"] = fmt.Sprintf("%d", cfg.limit)
	}
	if cfg.offset > 0 {
		params["offset"] = fmt.Sprintf("%d", cfg.offset)
	}
	if cfg.sort != "" {
		params["sort"] = cfg.sort
	}
	if cfg.order != "" {
		params["order"] = cfg.order
	}

	var resp taskListResponse
	if err := s.client.doGet(ctx, "/api/v3/vscanner/tasks", params, &resp); err != nil {
		return nil, err
	}

	return resp.Tasks, nil
}

// Get retrieves a task by ID.
func (s *TaskService) Get(ctx context.Context, projectID, taskID string) (*Task, error) {
	params := map[string]string{
		"projectId": projectID,
		"taskId":    taskID,
	}

	var task Task
	if err := s.client.doGet(ctx, "/api/v3/vscanner/task", params, &task); err != nil {
		return nil, err
	}

	return &task, nil
}

// Create creates a new task.
func (s *TaskService) Create(ctx context.Context, projectID string, req *TaskRequest) (*Task, error) {
	if req == nil {
		return nil, fmt.Errorf("task request is required")
	}

	createReq := struct {
		ProjectID string `json:"projectId"`
		*TaskRequest
	}{
		ProjectID:   projectID,
		TaskRequest: req,
	}

	var task Task
	if err := s.client.doPost(ctx, "/api/v3/vscanner/task/create", createReq, &task); err != nil {
		return nil, err
	}

	return &task, nil
}

// Update updates an existing task.
func (s *TaskService) Update(ctx context.Context, projectID, taskID string, req *TaskRequest) (*Task, error) {
	if req == nil {
		return nil, fmt.Errorf("task request is required")
	}

	updateReq := struct {
		ProjectID string `json:"projectId"`
		TaskID    string `json:"taskId"`
		*TaskRequest
	}{
		ProjectID:   projectID,
		TaskID:      taskID,
		TaskRequest: req,
	}

	var task Task
	if err := s.client.doPut(ctx, "/api/v3/vscanner/task/update", updateReq, &task); err != nil {
		return nil, err
	}

	return &task, nil
}

// Start starts a task.
func (s *TaskService) Start(ctx context.Context, projectID, taskID string) error {
	req := map[string]string{
		"projectId": projectID,
		"taskId":    taskID,
	}

	return s.client.doPost(ctx, "/api/v3/vscanner/task/start", req, nil)
}

// Stop stops a running task.
func (s *TaskService) Stop(ctx context.Context, projectID, taskID string) error {
	req := map[string]string{
		"projectId": projectID,
		"taskId":    taskID,
	}

	return s.client.doPost(ctx, "/api/v3/vscanner/task/stop", req, nil)
}

// Delete removes a task.
func (s *TaskService) Delete(ctx context.Context, projectID, taskID string) error {
	req := map[string]string{
		"projectId": projectID,
		"taskId":    taskID,
	}

	return s.client.doPost(ctx, "/api/v3/vscanner/task/delete", req, nil)
}
