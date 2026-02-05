package vulners

import (
	"context"
	"fmt"
)

// WebhookService provides methods for webhook management.
type WebhookService struct {
	transport *transport
}

// webhookListResponse represents the webhook list response.
type webhookListResponse struct {
	Webhooks []Webhook `json:"webhooks"`
}

// webhookAddRequest represents a webhook add request.
type webhookAddRequest struct {
	Query string `json:"query"`
}

// webhookEnableRequest represents a webhook enable/disable request.
type webhookEnableRequest struct {
	ID     string `json:"id"`
	Active bool   `json:"active"`
}

// webhookDeleteRequest represents a webhook delete request.
type webhookDeleteRequest struct {
	ID string `json:"id"`
}

// webhookReadRequest represents a webhook read request.
type webhookReadRequest struct {
	ID         string `json:"id"`
	NewestOnly bool   `json:"newestOnly,omitempty"`
}

// List returns all configured webhooks.
func (s *WebhookService) List(ctx context.Context) ([]Webhook, error) {
	var resp webhookListResponse
	if err := s.transport.doPost(ctx, "/api/v3/webhook/list/", nil, &resp); err != nil {
		return nil, err
	}

	return resp.Webhooks, nil
}

// Add creates a new webhook with the given query.
func (s *WebhookService) Add(ctx context.Context, query string) (*Webhook, error) {
	if err := validateRequired("query", query); err != nil {
		return nil, err
	}

	req := webhookAddRequest{
		Query: query,
	}

	var webhook Webhook
	if err := s.transport.doPost(ctx, "/api/v3/webhook/add/", req, &webhook); err != nil {
		return nil, err
	}

	return &webhook, nil
}

// Enable enables or disables a webhook.
func (s *WebhookService) Enable(ctx context.Context, id string, active bool) error {
	if err := validateRequired("id", id); err != nil {
		return err
	}

	req := webhookEnableRequest{
		ID:     id,
		Active: active,
	}

	return s.transport.doPost(ctx, "/api/v3/webhook/enable/", req, nil)
}

// Delete removes a webhook.
func (s *WebhookService) Delete(ctx context.Context, id string) error {
	if err := validateRequired("id", id); err != nil {
		return err
	}

	req := webhookDeleteRequest{
		ID: id,
	}

	return s.transport.doPost(ctx, "/api/v3/webhook/delete/", req, nil)
}

// Read retrieves data from a webhook.
// If newestOnly is true, only the newest data since the last read is returned.
func (s *WebhookService) Read(ctx context.Context, id string, newestOnly bool) (*WebhookData, error) {
	if err := validateRequired("id", id); err != nil {
		return nil, err
	}

	req := webhookReadRequest{
		ID:         id,
		NewestOnly: newestOnly,
	}

	var data WebhookData
	if err := s.transport.doPost(ctx, "/api/v3/webhook/read/", req, &data); err != nil {
		return nil, err
	}

	return &data, nil
}

// GetByID retrieves a specific webhook by its ID.
func (s *WebhookService) GetByID(ctx context.Context, id string) (*Webhook, error) {
	if err := validateRequired("id", id); err != nil {
		return nil, err
	}

	webhooks, err := s.List(ctx)
	if err != nil {
		return nil, err
	}

	for _, wh := range webhooks {
		if wh.ID == id {
			return &wh, nil
		}
	}

	return nil, fmt.Errorf("webhook with ID %s not found", id)
}
