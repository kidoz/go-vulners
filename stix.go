package vulners

import (
	"context"
	"encoding/json"
	"fmt"
)

// StixService provides methods for STIX bundle generation.
type StixService struct {
	transport *transport
}

// StixOption is a functional option for STIX operations.
type StixOption func(*stixConfig)

type stixConfig struct {
	version string
}

// WithSTIXVersion sets the STIX version for the bundle.
func WithSTIXVersion(version string) StixOption {
	return func(c *stixConfig) {
		c.version = version
	}
}

// StixBundle represents a STIX bundle.
type StixBundle struct {
	Type    string            `json:"type"`
	ID      string            `json:"id"`
	Objects []json.RawMessage `json:"objects"`
}

// stixV4Response wraps StixBundle for the v4 API format.
// The v4 /api/v4/stix/bundle endpoint returns {"result": {"type":"bundle","id":"...","objects":[...]}}
// instead of the v3 {"result": "OK", "data": {...}} format.
type stixV4Response struct {
	Result json.RawMessage `json:"result"`
}

// MakeBundleByID generates a STIX bundle for a given bulletin ID.
func (s *StixService) MakeBundleByID(ctx context.Context, bulletinID string, opts ...StixOption) (*StixBundle, error) {
	if err := validateRequired("bulletinID", bulletinID); err != nil {
		return nil, err
	}

	cfg := &stixConfig{
		version: "2.1",
	}

	for _, opt := range opts {
		opt(cfg)
	}

	params := map[string]string{"id": bulletinID}

	var resp stixV4Response
	if err := s.transport.doGet(ctx, "/api/v4/stix/bundle", params, &resp); err != nil {
		return nil, err
	}

	return decodeSTIXBundle(resp.Result)
}

// MakeBundleByCVE generates a STIX bundle for a given CVE ID.
func (s *StixService) MakeBundleByCVE(ctx context.Context, cveID string, opts ...StixOption) (*StixBundle, error) {
	if err := validateRequired("cveID", cveID); err != nil {
		return nil, err
	}

	return s.MakeBundleByID(ctx, cveID, opts...)
}

func decodeSTIXBundle(raw json.RawMessage) (*StixBundle, error) {
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err == nil {
		raw = json.RawMessage(encoded)
	}

	var bundle StixBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("failed to decode STIX bundle: %w", err)
	}
	return &bundle, nil
}
