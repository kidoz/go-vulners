package vscanner

import (
	"context"
	"fmt"
)

// ProjectService provides methods for managing VScanner projects.
type ProjectService struct {
	client *Client
}

// Project represents a VScanner project.
type Project struct {
	ID           string        `json:"id,omitempty"`
	Name         string        `json:"name,omitempty"`
	Description  string        `json:"description,omitempty"`
	Created      *Time         `json:"created,omitempty"`
	Modified     *Time         `json:"modified,omitempty"`
	TaskCount    int           `json:"taskCount,omitempty"`
	HostCount    int           `json:"hostCount,omitempty"`
	VulnCount    int           `json:"vulnCount,omitempty"`
	Notification *Notification `json:"notification,omitempty"`
	License      string        `json:"license,omitempty"`
}

// Notification represents notification settings for a project.
type Notification struct {
	Enabled    bool     `json:"enabled,omitempty"`
	Emails     []string `json:"emails,omitempty"`
	OnComplete bool     `json:"onComplete,omitempty"`
	OnError    bool     `json:"onError,omitempty"`
}

// ProjectRequest represents a request to create or update a project.
type ProjectRequest struct {
	Name         string        `json:"name,omitempty"`
	Description  string        `json:"description,omitempty"`
	Notification *Notification `json:"notification,omitempty"`
	License      string        `json:"license,omitempty"`
}

// ListOption is a functional option for list operations.
type ListOption func(*listConfig)

type listConfig struct {
	limit  int
	offset int
	sort   string
	order  string
}

// WithListLimit sets the limit for list operations.
func WithListLimit(limit int) ListOption {
	return func(c *listConfig) {
		c.limit = limit
	}
}

// WithListOffset sets the offset for list operations.
func WithListOffset(offset int) ListOption {
	return func(c *listConfig) {
		c.offset = offset
	}
}

// WithListSort sets the sort field and order for list operations.
func WithListSort(field string, ascending bool) ListOption {
	return func(c *listConfig) {
		c.sort = field
		if ascending {
			c.order = "asc"
		} else {
			c.order = "desc"
		}
	}
}

// projectListResponse represents the project list response.
type projectListResponse struct {
	Projects []Project `json:"projects"`
	Total    int       `json:"total,omitempty"`
}

// List returns all projects.
func (s *ProjectService) List(ctx context.Context, opts ...ListOption) ([]Project, error) {
	cfg := &listConfig{
		limit: 100,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	params := map[string]string{}
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

	var resp projectListResponse
	if err := s.client.doGet(ctx, "/api/v3/vscanner/projects", params, &resp); err != nil {
		return nil, err
	}

	return resp.Projects, nil
}

// Get retrieves a project by ID.
func (s *ProjectService) Get(ctx context.Context, id string) (*Project, error) {
	params := map[string]string{
		"id": id,
	}

	var project Project
	if err := s.client.doGet(ctx, "/api/v3/vscanner/project", params, &project); err != nil {
		return nil, err
	}

	return &project, nil
}

// Create creates a new project.
func (s *ProjectService) Create(ctx context.Context, req *ProjectRequest) (*Project, error) {
	if req == nil {
		return nil, fmt.Errorf("project request is required")
	}

	var project Project
	if err := s.client.doPost(ctx, "/api/v3/vscanner/project/create", req, &project); err != nil {
		return nil, err
	}

	return &project, nil
}

// Update updates an existing project.
func (s *ProjectService) Update(ctx context.Context, id string, req *ProjectRequest) (*Project, error) {
	if req == nil {
		return nil, fmt.Errorf("project request is required")
	}

	updateReq := struct {
		ID string `json:"id"`
		*ProjectRequest
	}{
		ID:             id,
		ProjectRequest: req,
	}

	var project Project
	if err := s.client.doPut(ctx, "/api/v3/vscanner/project/update", updateReq, &project); err != nil {
		return nil, err
	}

	return &project, nil
}

// Delete removes a project.
func (s *ProjectService) Delete(ctx context.Context, id string) error {
	req := map[string]string{
		"id": id,
	}

	return s.client.doPost(ctx, "/api/v3/vscanner/project/delete", req, nil)
}
