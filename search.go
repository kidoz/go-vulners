package vulners

import (
	"context"
	"fmt"
	"strings"
)

// SearchService provides methods for searching the Vulners database.
type SearchService struct {
	transport *transport
}

// SearchOption is a functional option for search operations.
type SearchOption func(*searchConfig)

type searchConfig struct {
	limit     int
	offset    int
	fields    []string
	sort      string
	ascending bool
}

// WithLimit sets the maximum number of results to return.
// For SearchBulletins, this controls the page size (default 20).
// For SearchBulletinsAll, this controls the total result count:
//   - limit > 0: return at most this many results
//   - limit = 0: return empty result immediately (no API calls)
//   - limit < 0 or not set: return all matching results
func WithLimit(limit int) SearchOption {
	return func(c *searchConfig) {
		c.limit = limit
	}
}

// WithOffset sets the offset for pagination.
func WithOffset(offset int) SearchOption {
	return func(c *searchConfig) {
		c.offset = offset
	}
}

// WithFields sets the fields to return in results.
func WithFields(fields ...string) SearchOption {
	return func(c *searchConfig) {
		c.fields = fields
	}
}

// WithSort sets the sort field for results.
func WithSort(field string, ascending bool) SearchOption {
	return func(c *searchConfig) {
		c.sort = field
		c.ascending = ascending
	}
}

// searchRequest represents a search API request.
type searchRequest struct {
	Query  string   `json:"query"`
	Skip   int      `json:"skip,omitempty"`
	Size   int      `json:"size,omitempty"`
	Fields []string `json:"fields,omitempty"`
	Sort   string   `json:"sort,omitempty"`
	Order  string   `json:"order,omitempty"`
}

// searchResponse represents the search API response data.
type searchResponse struct {
	Results []Bulletin `json:"results"`
	Search  []Bulletin `json:"search"` // Legacy field name (fallback)
	Total   int        `json:"total"`
	Took    int        `json:"took,omitempty"`
}

// idSearchRequest represents a search-by-ID API request.
type idSearchRequest struct {
	ID     interface{} `json:"id"` // can be string or []string
	Fields []string    `json:"fields,omitempty"`
}

// idSearchResponse represents the search-by-ID API response.
type idSearchResponse struct {
	Documents map[string]Bulletin `json:"documents"`
	Total     int                 `json:"total,omitempty"`
}

// referencesResponse represents the references API response.
type referencesResponse struct {
	References []string `json:"references"`
}

// historyResponse represents the history API response.
type historyResponse struct {
	History []HistoryEntry `json:"history,omitempty"`
}

// SearchBulletins searches for bulletins using Lucene query syntax.
func (s *SearchService) SearchBulletins(ctx context.Context, query string, opts ...SearchOption) (*SearchResult, error) {
	cfg := &searchConfig{
		limit:  20,
		offset: 0,
		fields: strings.Split(DefaultFields, ","),
	}

	for _, opt := range opts {
		opt(cfg)
	}

	req := searchRequest{
		Query:  query,
		Skip:   cfg.offset,
		Size:   cfg.limit,
		Fields: cfg.fields,
	}

	if cfg.sort != "" {
		req.Sort = cfg.sort
		if cfg.ascending {
			req.Order = "asc"
		} else {
			req.Order = "desc"
		}
	}

	var resp searchResponse
	if err := s.transport.doPost(ctx, "/api/v3/search/lucene/", req, &resp); err != nil {
		return nil, err
	}

	// Use Results field (v3 API), fall back to Search field (legacy)
	bulletins := resp.Results
	if len(bulletins) == 0 && len(resp.Search) > 0 {
		bulletins = resp.Search
	}

	return &SearchResult{
		Total:     resp.Total,
		Bulletins: bulletins,
		Took:      resp.Took,
	}, nil
}

// SearchBulletinsAll returns all results for a query using pagination.
// Use with caution as this may make many API calls for large result sets.
//
// The limit can be controlled with WithLimit:
//   - WithLimit(n) where n > 0: return at most n results
//   - WithLimit(0): return empty result (no API calls made)
//   - No WithLimit option: return all matching results (unlimited)
func (s *SearchService) SearchBulletinsAll(ctx context.Context, query string, opts ...SearchOption) ([]Bulletin, error) {
	const pageSize = 100

	cfg := &searchConfig{
		limit:  -1, // unlimited by default
		offset: 0,
		fields: strings.Split(DefaultFields, ","),
	}

	for _, opt := range opts {
		opt(cfg)
	}

	// Handle explicit limit of 0 - return empty result
	if cfg.limit == 0 {
		return []Bulletin{}, nil
	}

	var allBulletins []Bulletin
	offset := cfg.offset

	for {
		req := searchRequest{
			Query:  query,
			Skip:   offset,
			Size:   pageSize,
			Fields: cfg.fields,
		}

		if cfg.sort != "" {
			req.Sort = cfg.sort
			if cfg.ascending {
				req.Order = "asc"
			} else {
				req.Order = "desc"
			}
		}

		var resp searchResponse
		if err := s.transport.doPost(ctx, "/api/v3/search/lucene/", req, &resp); err != nil {
			return nil, err
		}

		// Use Results field (v3 API), fall back to Search field (legacy)
		bulletins := resp.Results
		if len(bulletins) == 0 && len(resp.Search) > 0 {
			bulletins = resp.Search
		}

		allBulletins = append(allBulletins, bulletins...)

		// Check if we've hit the user-specified limit
		if cfg.limit > 0 && len(allBulletins) >= cfg.limit {
			allBulletins = allBulletins[:cfg.limit]
			break
		}

		// Check if we've retrieved all results:
		// - No results returned means no more data
		// - We've reached or exceeded the total count
		// - Got fewer results than requested (last page)
		if len(bulletins) == 0 {
			break
		}
		if resp.Total > 0 && len(allBulletins) >= resp.Total {
			break
		}
		if len(bulletins) < pageSize {
			break
		}

		offset += pageSize
	}

	return allBulletins, nil
}

// SearchExploits searches specifically for exploits.
func (s *SearchService) SearchExploits(ctx context.Context, query string, opts ...SearchOption) (*SearchResult, error) {
	// Modify query to filter for exploits only
	exploitQuery := fmt.Sprintf("(%s) AND bulletinFamily:exploit", query)
	return s.SearchBulletins(ctx, exploitQuery, opts...)
}

// GetBulletin retrieves a single bulletin by ID.
func (s *SearchService) GetBulletin(ctx context.Context, id string, opts ...SearchOption) (*Bulletin, error) {
	if err := validateRequired("id", id); err != nil {
		return nil, err
	}

	cfg := &searchConfig{
		fields: strings.Split(DefaultFields, ","),
	}

	for _, opt := range opts {
		opt(cfg)
	}

	req := idSearchRequest{
		ID:     id,
		Fields: cfg.fields,
	}

	var resp idSearchResponse
	if err := s.transport.doPost(ctx, "/api/v3/search/id/", req, &resp); err != nil {
		return nil, err
	}

	bulletin, ok := resp.Documents[id]
	if !ok {
		return nil, ErrNotFound
	}

	return &bulletin, nil
}

// GetMultipleBulletins retrieves multiple bulletins by their IDs.
func (s *SearchService) GetMultipleBulletins(ctx context.Context, ids []string, opts ...SearchOption) (map[string]Bulletin, error) {
	if len(ids) == 0 {
		return make(map[string]Bulletin), nil
	}

	cfg := &searchConfig{
		fields: strings.Split(DefaultFields, ","),
	}

	for _, opt := range opts {
		opt(cfg)
	}

	req := idSearchRequest{
		ID:     ids,
		Fields: cfg.fields,
	}

	var resp idSearchResponse
	if err := s.transport.doPost(ctx, "/api/v3/search/id/", req, &resp); err != nil {
		return nil, err
	}

	return resp.Documents, nil
}

// GetBulletinReferences retrieves references for a bulletin.
func (s *SearchService) GetBulletinReferences(ctx context.Context, id string) ([]string, error) {
	if err := validateRequired("id", id); err != nil {
		return nil, err
	}

	req := map[string]string{
		"id": id,
	}

	var resp referencesResponse
	if err := s.transport.doPost(ctx, "/api/v3/search/references/", req, &resp); err != nil {
		return nil, err
	}

	return resp.References, nil
}

// GetBulletinHistory retrieves the change history for a bulletin.
func (s *SearchService) GetBulletinHistory(ctx context.Context, id string) ([]HistoryEntry, error) {
	if err := validateRequired("id", id); err != nil {
		return nil, err
	}

	params := map[string]string{
		"id": id,
	}

	var resp historyResponse
	if err := s.transport.doGet(ctx, "/api/v3/search/history/", params, &resp); err != nil {
		return nil, err
	}

	return resp.History, nil
}
