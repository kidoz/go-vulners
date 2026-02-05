package vulners

import (
	"context"
	"time"
)

// ArchiveService provides methods for fetching vulnerability collections.
type ArchiveService struct {
	transport *transport
}

// CollectionType represents a type of vulnerability collection.
type CollectionType string

// Collection types supported by the Vulners API.
const (
	CollectionCVE       CollectionType = "cve"
	CollectionExploit   CollectionType = "exploit"
	CollectionNVD       CollectionType = "nvd"
	CollectionCisco     CollectionType = "cisco"
	CollectionDebian    CollectionType = "debian"
	CollectionUbuntu    CollectionType = "ubuntu"
	CollectionRedhat    CollectionType = "redhat"
	CollectionFedora    CollectionType = "fedora"
	CollectionSuse      CollectionType = "suse"
	CollectionOracle    CollectionType = "oracle"
	CollectionAmazon    CollectionType = "amazon"
	CollectionGentoo    CollectionType = "gentoo"
	CollectionArch      CollectionType = "arch"
	CollectionAlpine    CollectionType = "alpine"
	CollectionFreeBSD   CollectionType = "freebsd"
	CollectionMicrosoft CollectionType = "microsoft"
	CollectionApple     CollectionType = "apple"
	CollectionVMware    CollectionType = "vmware"
)

// collectionResponse represents the collection API response.
type collectionResponse struct {
	Bulletins []Bulletin `json:"bulletins,omitempty"`
	Total     int        `json:"total,omitempty"`
}

// FetchCollection fetches all bulletins for a given collection type.
func (s *ArchiveService) FetchCollection(ctx context.Context, collType CollectionType) ([]Bulletin, error) {
	params := map[string]string{
		"type": string(collType),
	}

	var resp collectionResponse
	if err := s.transport.doGet(ctx, "/api/v4/archive/collection", params, &resp); err != nil {
		return nil, err
	}

	return resp.Bulletins, nil
}

// FetchCollectionUpdate fetches bulletins updated after a given timestamp.
// The after parameter must be within the last 25 hours per API requirements.
func (s *ArchiveService) FetchCollectionUpdate(ctx context.Context, collType CollectionType, after time.Time) ([]Bulletin, error) {
	params := map[string]string{
		"type":  string(collType),
		"after": after.UTC().Format(time.RFC3339),
	}

	var resp collectionResponse
	if err := s.transport.doGet(ctx, "/api/v4/archive/collection-update", params, &resp); err != nil {
		return nil, err
	}

	return resp.Bulletins, nil
}
