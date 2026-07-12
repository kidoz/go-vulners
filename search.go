package vulners

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// SearchService provides methods for searching the Vulners database.
type SearchService struct {
	transport *transport
}

// SearchOption is a functional option for search operations.
type SearchOption func(*searchConfig)

// WebVulnerabilityOption is a functional option for web vulnerability searches.
type WebVulnerabilityOption func(*webVulnerabilityConfig)

type searchConfig struct {
	limit     int
	offset    int
	fields    []string
	sort      string
	ascending bool
}

type webVulnerabilityConfig struct {
	match   string
	config  []string
	catalog string
}

// WithWebVulnerabilityMatch sets the application matching mode to "partial" or "full".
func WithWebVulnerabilityMatch(match string) WebVulnerabilityOption {
	return func(c *webVulnerabilityConfig) {
		c.match = match
	}
}

// WithWebVulnerabilityConfig sets the named application matching configurations.
func WithWebVulnerabilityConfig(config ...string) WebVulnerabilityOption {
	return func(c *webVulnerabilityConfig) {
		c.config = config
	}
}

// WithWebVulnerabilityCatalog sets the application catalog to "official" or "extended".
func WithWebVulnerabilityCatalog(catalog string) WebVulnerabilityOption {
	return func(c *webVulnerabilityConfig) {
		c.catalog = catalog
	}
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

type searchHit struct {
	Source Bulletin `json:"_source"`
}

func (h *searchHit) UnmarshalJSON(data []byte) error {
	var wrapped struct {
		Source json.RawMessage `json:"_source"`
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return err
	}
	if len(wrapped.Source) > 0 {
		return json.Unmarshal(wrapped.Source, &h.Source)
	}
	return json.Unmarshal(data, &h.Source)
}

// searchResponse represents the search API response data.
type searchResponse struct {
	Results       []Bulletin  `json:"results"`
	Search        []searchHit `json:"search"`
	Total         int         `json:"total"`
	Took          int         `json:"took,omitempty"`
	MaxSearchSize int         `json:"maxSearchSize,omitempty"`
}

// idSearchRequest represents a search-by-ID API request.
type idSearchRequest struct {
	ID              interface{} `json:"id"` // can be string or []string
	Fields          []string    `json:"fields,omitempty"`
	References      bool        `json:"references,omitempty"`
	ReferenceFields []string    `json:"referenceFields,omitempty"`
}

// idSearchResponse represents the search-by-ID API response.
type idSearchResponse struct {
	Documents  map[string]Bulletin              `json:"documents"`
	References map[string]map[string][]Bulletin `json:"references,omitempty"`
	Total      int                              `json:"total,omitempty"`
}

// historyResponse represents the history API response.
type historyResponse struct {
	Result []HistoryEntry `json:"result"`
}

type webVulnerabilityRequest struct {
	Paths       []string    `json:"paths"`
	Application interface{} `json:"application,omitempty"`
	Match       string      `json:"match,omitempty"`
	Config      []string    `json:"config,omitempty"`
	Catalog     string      `json:"catalog,omitempty"`
}

type webVulnerabilityResponse struct {
	Result map[string][]WebVulnerability `json:"result"`
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

	bulletins := extractSearchBulletins(&resp)

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

		bulletins := extractSearchBulletins(&resp)

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
	exploitQuery := fmt.Sprintf("bulletinFamily:exploit AND (%s)", query)
	return s.SearchBulletins(ctx, exploitQuery, opts...)
}

// SearchExploitsAll returns all matching exploit bulletins using pagination.
func (s *SearchService) SearchExploitsAll(ctx context.Context, query string, opts ...SearchOption) ([]Bulletin, error) {
	exploitQuery := fmt.Sprintf("bulletinFamily:exploit AND (%s)", query)
	return s.SearchBulletinsAll(ctx, exploitQuery, opts...)
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

// GetMultipleBulletinsWithReferences retrieves bulletins and their references in one request.
func (s *SearchService) GetMultipleBulletinsWithReferences(ctx context.Context, ids []string, opts ...SearchOption) (*BulletinsWithReferences, error) {
	if len(ids) == 0 {
		return &BulletinsWithReferences{
			Documents:  make(map[string]Bulletin),
			References: make(map[string]map[string][]Bulletin),
		}, nil
	}

	cfg := &searchConfig{fields: strings.Split(DefaultFields, ",")}
	for _, opt := range opts {
		opt(cfg)
	}

	req := idSearchRequest{
		ID:         ids,
		Fields:     cfg.fields,
		References: true,
	}
	var resp idSearchResponse
	if err := s.transport.doPost(ctx, "/api/v3/search/id/", req, &resp); err != nil {
		return nil, err
	}

	return &BulletinsWithReferences{
		Documents:  resp.Documents,
		References: resp.References,
	}, nil
}

// GetBulletinWithReferences retrieves one bulletin and all grouped reference bulletins.
func (s *SearchService) GetBulletinWithReferences(ctx context.Context, id string, opts ...SearchOption) (*BulletinsWithReferences, error) {
	if err := validateRequired("id", id); err != nil {
		return nil, err
	}
	return s.GetMultipleBulletinsWithReferences(ctx, []string{id}, opts...)
}

// GetKBSeeds returns superseded and superseding Microsoft KB identifiers.
func (s *SearchService) GetKBSeeds(ctx context.Context, id string) (*KBSeeds, error) {
	bulletin, err := s.GetBulletin(ctx, id, WithFields("superseeds", "parentseeds"))
	if err != nil {
		return nil, err
	}
	return &KBSeeds{Superseeds: bulletin.Superseeds, Parentseeds: bulletin.Parentseeds}, nil
}

// GetKBUpdates searches for Microsoft updates associated with a KB identifier.
func (s *SearchService) GetKBUpdates(ctx context.Context, id string, opts ...SearchOption) (*SearchResult, error) {
	if err := validateRequired("id", id); err != nil {
		return nil, err
	}
	return s.SearchBulletins(ctx, fmt.Sprintf("type:msupdate AND kb:(%s)", id), opts...)
}

// GetBulletinReferences retrieves references for a bulletin.
func (s *SearchService) GetBulletinReferences(ctx context.Context, id string) ([]string, error) {
	if err := validateRequired("id", id); err != nil {
		return nil, err
	}

	references, err := s.GetMultipleBulletinReferences(ctx, []string{id})
	if err != nil {
		return nil, err
	}

	var ids []string
	for _, bulletins := range references[id] {
		for i := range bulletins {
			ids = append(ids, bulletins[i].ID)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// GetMultipleBulletinReferences retrieves reference bulletins grouped by source ID and type.
func (s *SearchService) GetMultipleBulletinReferences(ctx context.Context, ids []string) (map[string]map[string][]Bulletin, error) {
	if len(ids) == 0 {
		return make(map[string]map[string][]Bulletin), nil
	}

	req := idSearchRequest{
		ID:         ids,
		Fields:     []string{},
		References: true,
	}

	var resp idSearchResponse
	if err := s.transport.doPost(ctx, "/api/v3/search/id/", req, &resp); err != nil {
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

	return resp.Result, nil
}

// GetWebVulnerabilities searches for vulnerabilities related to web paths.
// Application may be nil, a CPE string, a target alias, or an AuditItem criteria value.
func (s *SearchService) GetWebVulnerabilities(ctx context.Context, paths []string, application interface{}, opts ...WebVulnerabilityOption) (map[string][]WebVulnerability, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("%w: paths are required", ErrInvalidInput)
	}

	cfg := &webVulnerabilityConfig{
		match:   "partial",
		catalog: "official",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	req := webVulnerabilityRequest{
		Paths:       paths,
		Application: application,
		Match:       cfg.match,
		Config:      cfg.config,
		Catalog:     cfg.catalog,
	}
	var resp webVulnerabilityResponse
	if err := s.transport.doPost(ctx, "/api/v4/search/web-vulns/", req, &resp); err != nil {
		return nil, err
	}
	return resp.Result, nil
}

func extractSearchBulletins(resp *searchResponse) []Bulletin {
	if len(resp.Results) > 0 {
		return resp.Results
	}

	bulletins := make([]Bulletin, 0, len(resp.Search))
	for i := range resp.Search {
		bulletins = append(bulletins, resp.Search[i].Source)
	}
	return bulletins
}
