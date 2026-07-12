package vulners

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// FetchCollection fetches all bulletins for a given collection type.
func (s *ArchiveService) FetchCollection(ctx context.Context, collType CollectionType) ([]Bulletin, error) {
	params := map[string]string{
		"type": string(collType),
	}

	return s.fetchArchive(ctx, "/api/v4/archive/collection", params)
}

// FetchCollectionUpdate fetches bulletins updated after a given timestamp.
// The after parameter must be within the last 25 hours per API requirements.
func (s *ArchiveService) FetchCollectionUpdate(ctx context.Context, collType CollectionType, after time.Time) ([]Bulletin, error) {
	params := map[string]string{
		"type":  string(collType),
		"after": after.UTC().Format(time.RFC3339),
	}

	return s.fetchArchive(ctx, "/api/v4/archive/collection-update", params)
}

func (s *ArchiveService) fetchArchive(ctx context.Context, path string, params map[string]string) ([]Bulletin, error) {
	data, err := s.transport.doGetBytes(ctx, path, params)
	if err != nil {
		return nil, err
	}

	var reader io.Reader = bytes.NewReader(data)
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		gzReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to open archive gzip stream: %w", err)
		}
		defer func() { _ = gzReader.Close() }()
		reader = gzReader
	}

	decoded, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read archive stream: %w", err)
	}
	decoded = bytes.TrimSpace(decoded)
	if len(decoded) == 0 {
		return []Bulletin{}, nil
	}
	if decoded[0] == '[' {
		var bulletins []Bulletin
		if err := json.Unmarshal(decoded, &bulletins); err != nil {
			return nil, fmt.Errorf("failed to decode archive array: %w", err)
		}
		return bulletins, nil
	}

	var bulletins []Bulletin
	scanner := bufio.NewScanner(bytes.NewReader(decoded))
	scanner.Buffer(make([]byte, 64*1024), maxResponseSize)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var bulletin Bulletin
		if err := json.Unmarshal(line, &bulletin); err != nil {
			return nil, fmt.Errorf("failed to decode archive entry: %w", err)
		}
		bulletins = append(bulletins, bulletin)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read archive stream: %w", err)
	}
	return bulletins, nil
}
