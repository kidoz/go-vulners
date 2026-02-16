package vulners

import (
	"context"
	"encoding/json"
	"strconv"
)

// MiscService provides miscellaneous API operations.
type MiscService struct {
	transport *transport
}

// CPEOption is a functional option for CPE search operations.
type CPEOption func(*cpeConfig)

type cpeConfig struct {
	size   int
	vendor string
}

// WithCPESize sets the maximum number of CPE results to return.
func WithCPESize(size int) CPEOption {
	return func(c *cpeConfig) {
		c.size = size
	}
}

// WithMaxSize sets the maximum number of CPE results to return.
//
// Deprecated: Use WithCPESize instead.
func WithMaxSize(maxSize int) CPEOption {
	return func(c *cpeConfig) {
		c.size = maxSize
	}
}

// WithVendor sets the vendor name for CPE search.
func WithVendor(vendor string) CPEOption {
	return func(c *cpeConfig) {
		c.vendor = vendor
	}
}

// cpeSearchResponse represents the CPE search API response fields.
type cpeSearchResponse struct {
	BestMatch string   `json:"best_match,omitempty"`
	CPE       []string `json:"cpe,omitempty"`
}

// cpeV4Response wraps cpeSearchResponse for the v4 API format.
// The v4 /api/v4/search/cpe endpoint returns {"result": {"best_match": "...", "cpe": [...]}}
// instead of the v3 {"result": "OK", "data": {...}} format.
type cpeV4Response struct {
	Result cpeSearchResponse `json:"result"`
}

// aiScoreRequest represents an AI score request.
type aiScoreRequest struct {
	Text string `json:"text"`
}

// aiScoreResponse represents the AI score response.
type aiScoreResponse struct {
	Score *AIScore `json:"score,omitempty"`
}

// suggestionRequest represents a suggestion request.
type suggestionRequest struct {
	FieldName string `json:"fieldName"`
}

// suggestionResponse represents a suggestion response.
type suggestionResponse struct {
	Suggestions []string `json:"suggestions"`
}

// autocompleteRequest represents an autocomplete request.
type autocompleteRequest struct {
	Query string `json:"query"`
}

// autocompleteResponse represents the autocomplete API response.
// Note: OpenAPI spec shows array but actual API returns wrapped object.
// The suggestions field may contain arrays of strings (for multi-part suggestions).
type autocompleteResponse struct {
	Suggestions  json.RawMessage `json:"suggestions,omitempty"`
	Autocomplete json.RawMessage `json:"autocomplete,omitempty"`
}

// CPESearchResult represents the result of a CPE search.
type CPESearchResult struct {
	BestMatch string   // Best matching CPE string
	CPEs      []string // List of matching CPE strings
}

// SearchCPE searches for CPE (Common Platform Enumeration) entries.
// Both product and vendor are required parameters per the API spec.
func (s *MiscService) SearchCPE(ctx context.Context, product, vendor string, opts ...CPEOption) (*CPESearchResult, error) {
	if err := validateRequired("product", product); err != nil {
		return nil, err
	}
	if err := validateRequired("vendor", vendor); err != nil {
		return nil, err
	}

	cfg := &cpeConfig{
		size: 20,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	params := map[string]string{
		"product": product,
		"vendor":  vendor,
	}

	if cfg.size > 0 {
		params["size"] = strconv.Itoa(cfg.size)
	}

	var resp cpeV4Response
	if err := s.transport.doGet(ctx, "/api/v4/search/cpe", params, &resp); err != nil {
		return nil, err
	}

	return &CPESearchResult{
		BestMatch: resp.Result.BestMatch,
		CPEs:      resp.Result.CPE,
	}, nil
}

// GetAIScore gets an AI-generated vulnerability score for the given text.
func (s *MiscService) GetAIScore(ctx context.Context, text string) (*AIScore, error) {
	if err := validateRequired("text", text); err != nil {
		return nil, err
	}

	req := aiScoreRequest{
		Text: text,
	}

	var resp aiScoreResponse
	if err := s.transport.doPost(ctx, "/api/v3/ai/scoretext/", req, &resp); err != nil {
		return nil, err
	}

	return resp.Score, nil
}

// GetSuggestion gets suggestions for a specific field.
func (s *MiscService) GetSuggestion(ctx context.Context, fieldName string) ([]string, error) {
	if err := validateRequired("fieldName", fieldName); err != nil {
		return nil, err
	}

	req := suggestionRequest{
		FieldName: fieldName,
	}

	var resp suggestionResponse
	if err := s.transport.doPost(ctx, "/api/v3/search/suggest/", req, &resp); err != nil {
		return nil, err
	}

	return resp.Suggestions, nil
}

// QueryAutocomplete provides query autocomplete suggestions.
func (s *MiscService) QueryAutocomplete(ctx context.Context, query string) ([]string, error) {
	req := autocompleteRequest{
		Query: query,
	}

	var resp autocompleteResponse
	if err := s.transport.doPost(ctx, "/api/v3/search/autocomplete/", req, &resp); err != nil {
		return nil, err
	}

	// Parse suggestions from the raw JSON (can be []string or [][]string)
	suggestions := parseSuggestions(resp.Suggestions)
	if len(suggestions) > 0 {
		return suggestions, nil
	}

	// Try autocomplete field as fallback
	return parseSuggestions(resp.Autocomplete), nil
}

// parseSuggestions parses autocomplete suggestions from raw JSON.
// Handles various formats: []string, [][]string, [["text", bool], ...], []object
func parseSuggestions(data json.RawMessage) []string {
	if len(data) == 0 {
		return nil
	}

	// Try parsing as simple string array first
	var simple []string
	if err := json.Unmarshal(data, &simple); err == nil {
		return simple
	}

	// Try parsing as array of arrays with mixed types [["text", false], ...]
	// This is the actual format returned by the Vulners API
	var mixedNested [][]interface{}
	if err := json.Unmarshal(data, &mixedNested); err == nil {
		result := make([]string, 0, len(mixedNested))
		for _, arr := range mixedNested {
			if len(arr) > 0 {
				// First element is the suggestion string
				if s, ok := arr[0].(string); ok {
					result = append(result, s)
				}
			}
		}
		if len(result) > 0 {
			return result
		}
	}

	// Try parsing as array of string arrays
	var nested [][]string
	if err := json.Unmarshal(data, &nested); err == nil {
		result := make([]string, 0, len(nested))
		for _, arr := range nested {
			if len(arr) > 0 {
				result = append(result, arr[0])
			}
		}
		return result
	}

	// Try parsing as array of objects with a text/value field
	var objects []map[string]interface{}
	if err := json.Unmarshal(data, &objects); err == nil {
		result := make([]string, 0, len(objects))
		for _, obj := range objects {
			// Try common field names
			for _, key := range []string{"text", "value", "suggestion", "title"} {
				if v, ok := obj[key].(string); ok {
					result = append(result, v)
					break
				}
			}
		}
		return result
	}

	return nil
}
