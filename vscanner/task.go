package vscanner

import (
	"context"
	"fmt"
	"net/url"
)

// TaskService provides methods for managing VScanner tasks.
type TaskService struct {
	client *Client
}

// Task represents a VScanner scanning task.
type Task struct {
	ID        string   `json:"_id,omitempty"`
	Name      string   `json:"name,omitempty"`
	ProjectID string   `json:"project_id,omitempty"`
	Networks  []string `json:"networks,omitempty"`
	Ports     []string `json:"ports,omitempty"`
	Timing    string   `json:"timing,omitempty"`
	// Schedule is a crontab-format string.
	Schedule  string `json:"schedule,omitempty"`
	Enabled   bool   `json:"enabled,omitempty"`
	ContextID string `json:"context_id,omitempty"`
}

// TaskRequest represents a request to create or update a task.
type TaskRequest struct {
	Name     string   `json:"name"`
	Networks []string `json:"networks"`
	Ports    []string `json:"ports"`
	// Schedule is a crontab-format string.
	Schedule string `json:"schedule"`
	Timing   string `json:"timing"`
	Enabled  bool   `json:"enabled"`
}

func tasksPath(projectID string) string {
	return projectsBasePath + url.PathEscape(projectID) + "/tasks"
}

func taskPath(projectID, taskID string) string {
	return tasksPath(projectID) + "/" + url.PathEscape(taskID)
}

// List returns tasks for a project.
func (s *TaskService) List(ctx context.Context, projectID string, opts ...ListOption) ([]Task, error) {
	cfg := newListConfig(opts...)

	var tasks []Task
	if err := s.client.doGet(ctx, tasksPath(projectID), cfg.params(), &tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

// Create creates a new task in a project.
func (s *TaskService) Create(ctx context.Context, projectID string, req *TaskRequest) (*Task, error) {
	if req == nil {
		return nil, fmt.Errorf("vscanner: task request is required")
	}

	var task Task
	if err := s.client.doPost(ctx, tasksPath(projectID), req, &task); err != nil {
		return nil, err
	}
	return &task, nil
}

// Update updates an existing task.
func (s *TaskService) Update(ctx context.Context, projectID, taskID string, req *TaskRequest) (*Task, error) {
	if req == nil {
		return nil, fmt.Errorf("vscanner: task request is required")
	}

	var task Task
	if err := s.client.doPut(ctx, taskPath(projectID, taskID), req, &task); err != nil {
		return nil, err
	}
	return &task, nil
}

// Start schedules a task to run as soon as possible.
func (s *TaskService) Start(ctx context.Context, projectID, taskID string) (*Task, error) {
	var task Task
	if err := s.client.doPost(ctx, taskPath(projectID, taskID)+"/start", nil, &task); err != nil {
		return nil, err
	}
	return &task, nil
}

// Delete removes a task.
func (s *TaskService) Delete(ctx context.Context, projectID, taskID string) error {
	return s.client.doDelete(ctx, taskPath(projectID, taskID), nil)
}
