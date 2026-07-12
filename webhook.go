package vulners

import (
	"context"
	"fmt"
	"strconv"
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
	Query  string `json:"query"`
	APIKey string `json:"apiKey"`
}

// webhookEnableRequest represents a webhook enable/disable request.
type webhookEnableRequest struct {
	ID     string `json:"subscriptionid"`
	Active string `json:"active"`
	APIKey string `json:"apiKey"`
}

// webhookDeleteRequest represents a webhook delete request.
type webhookDeleteRequest struct {
	ID     string `json:"subscriptionid"`
	APIKey string `json:"apiKey"`
}

// List returns all configured webhooks.
func (s *WebhookService) List(ctx context.Context) ([]Webhook, error) {
	var resp webhookListResponse
	if err := s.transport.doGet(ctx, "/api/v3/subscriptions/listWebhookSubscriptions/", map[string]string{"apiKey": s.transport.apiKey}, &resp); err != nil {
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
	req.APIKey = s.transport.apiKey

	var webhook Webhook
	if err := s.transport.doPost(ctx, "/api/v3/subscriptions/addWebhookSubscription/", req, &webhook); err != nil {
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
		Active: strconv.FormatBool(active),
		APIKey: s.transport.apiKey,
	}

	return s.transport.doPost(ctx, "/api/v3/subscriptions/editWebhookSubscription/", req, nil)
}

// Delete removes a webhook.
func (s *WebhookService) Delete(ctx context.Context, id string) error {
	if err := validateRequired("id", id); err != nil {
		return err
	}

	req := webhookDeleteRequest{
		ID:     id,
		APIKey: s.transport.apiKey,
	}

	return s.transport.doPost(ctx, "/api/v3/subscriptions/removeWebhookSubscription/", req, nil)
}

// Read retrieves data from a webhook.
// If newestOnly is true, only the newest data since the last read is returned.
func (s *WebhookService) Read(ctx context.Context, id string, newestOnly bool) (*WebhookData, error) {
	if err := validateRequired("id", id); err != nil {
		return nil, err
	}

	params := map[string]string{
		"subscriptionid": id,
		"newest_only":    strconv.FormatBool(newestOnly),
		"apiKey":         s.transport.apiKey,
	}

	var data WebhookData
	if err := s.transport.doGet(ctx, "/api/v3/subscriptions/webhook", params, &data); err != nil {
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
