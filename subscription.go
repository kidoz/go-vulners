package vulners

import (
	"context"
	"fmt"
	"net/url"
)

// SubscriptionService provides methods for managing v4 subscriptions.
type SubscriptionService struct {
	transport *transport
}

// subscriptionListResponse represents the subscription list response.
type subscriptionListResponse struct {
	Subscriptions []Subscription `json:"subscriptions"`
}

// List returns all subscriptions.
func (s *SubscriptionService) List(ctx context.Context) ([]Subscription, error) {
	var resp subscriptionListResponse
	if err := s.transport.doGet(ctx, "/api/v4/subscription/list", nil, &resp); err != nil {
		return nil, err
	}

	return resp.Subscriptions, nil
}

// Get retrieves a subscription by ID.
func (s *SubscriptionService) Get(ctx context.Context, id string) (*Subscription, error) {
	if err := validateRequired("id", id); err != nil {
		return nil, err
	}

	params := map[string]string{
		"id": id,
	}

	var sub Subscription
	if err := s.transport.doGet(ctx, "/api/v4/subscription/get", params, &sub); err != nil {
		return nil, err
	}

	return &sub, nil
}

// Create creates a new subscription.
func (s *SubscriptionService) Create(ctx context.Context, req *SubscriptionRequest) (*Subscription, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: subscription request is required", ErrInvalidInput)
	}

	var sub Subscription
	if err := s.transport.doPost(ctx, "/api/v4/subscription/create", req, &sub); err != nil {
		return nil, err
	}

	return &sub, nil
}

// Update updates an existing subscription.
func (s *SubscriptionService) Update(ctx context.Context, id string, req *SubscriptionRequest) (*Subscription, error) {
	if err := validateRequired("id", id); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, fmt.Errorf("%w: subscription request is required", ErrInvalidInput)
	}

	updateReq := struct {
		ID string `json:"id"`
		*SubscriptionRequest
	}{
		ID:                  id,
		SubscriptionRequest: req,
	}

	var sub Subscription
	if err := s.transport.doPut(ctx, "/api/v4/subscription/update", updateReq, &sub); err != nil {
		return nil, err
	}

	return &sub, nil
}

// Delete removes a subscription.
func (s *SubscriptionService) Delete(ctx context.Context, id string) error {
	if err := validateRequired("id", id); err != nil {
		return err
	}

	path := fmt.Sprintf("/api/v4/subscription/delete?id=%s", url.QueryEscape(id))
	return s.transport.doDelete(ctx, path, nil)
}

// Enable enables or disables a subscription.
func (s *SubscriptionService) Enable(ctx context.Context, id string, active bool) error {
	if err := validateRequired("id", id); err != nil {
		return err
	}

	req := struct {
		ID     string `json:"id"`
		Active bool   `json:"active"`
	}{
		ID:     id,
		Active: active,
	}

	return s.transport.doPost(ctx, "/api/v4/subscription/enable", req, nil)
}
