//go:build integration

package vscanner

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestIntegration_ReadOnlySurface(t *testing.T) {
	apiKey := os.Getenv("VULNERS_API_KEY")
	if apiKey == "" {
		t.Skip("VULNERS_API_KEY environment variable not set")
	}

	client, err := NewClient(apiKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := client.GetLicenses(ctx); err != nil {
		t.Errorf("GetLicenses failed: %v", err)
	}
	if _, err := client.Project().List(ctx, WithListLimit(1)); err != nil {
		t.Logf("Project.List unavailable for this account/deployment: %v", err)
	}
}
