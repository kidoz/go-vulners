package vulners

import (
	"context"
	"fmt"
	"net/http"
)

// SubscriptionService provides methods for managing v4 subscriptions.
type SubscriptionService struct {
	transport *transport
}

// subscriptionListResponse represents the subscription list response.
type subscriptionListResponse struct {
	Result []Subscription `json:"result"`
}

type subscriptionV4Response struct {
	Result Subscription `json:"result"`
}

// List returns all subscriptions.
func (s *SubscriptionService) List(ctx context.Context) ([]Subscription, error) {
	var resp subscriptionListResponse
	if err := s.transport.doGet(ctx, "/api/v4/subscriptions/list/", nil, &resp); err != nil {
		return nil, err
	}

	return resp.Result, nil
}

// Get retrieves a subscription by ID.
func (s *SubscriptionService) Get(ctx context.Context, id string) (*Subscription, error) {
	if err := validateRequired("id", id); err != nil {
		return nil, err
	}

	params := map[string]string{
		"subscription_id": id,
	}

	var resp subscriptionV4Response
	if err := s.transport.doGet(ctx, "/api/v4/subscriptions/get/", params, &resp); err != nil {
		return nil, err
	}

	return &resp.Result, nil
}

// Create creates a new subscription.
func (s *SubscriptionService) Create(ctx context.Context, req *SubscriptionRequest) (*Subscription, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: subscription request is required", ErrInvalidInput)
	}

	var resp subscriptionV4Response
	if err := s.transport.doPost(ctx, "/api/v4/subscriptions/create/", req, &resp); err != nil {
		return nil, err
	}

	return &resp.Result, nil
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

	var resp subscriptionV4Response
	if err := s.transport.doPut(ctx, "/api/v4/subscriptions/update/", updateReq, &resp); err != nil {
		return nil, err
	}

	return &resp.Result, nil
}

// Delete removes a subscription.
func (s *SubscriptionService) Delete(ctx context.Context, id string) error {
	if err := validateRequired("id", id); err != nil {
		return err
	}

	return s.transport.do(ctx, http.MethodDelete, "/api/v4/subscriptions/delete/", map[string]string{"id": id}, nil)
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
