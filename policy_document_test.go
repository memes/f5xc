package f5xc_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/memes/f5xc"
)

// Verify that GetPolicyDocument can retrieve the standard 'Allow Volterra' policy that should be present in every tenant.
// NOTE: This test will be skipped if Volterra authentication values are missing from the environment.
func TestGetSecretPolicyDocument(t *testing.T) {
	t.Parallel()
	p12Path := os.Getenv("VOLT_API_P12_FILE")
	p12Passphrase := os.Getenv("VES_P12_PASSWORD")
	apiURL := os.Getenv("VOLT_API_URL")
	if p12Path == "" || p12Passphrase == "" || apiURL == "" {
		t.Skip("Required environment variables are not set")
	}
	client, err := f5xc.NewClient(
		f5xc.WithAPIEndpoint(apiURL),
		f5xc.WithP12Certificate(p12Path, p12Passphrase),
	)
	if err != nil {
		t.Errorf("Unexpected error raised by NewClient: %v", err)
	}
	t.Cleanup(client.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	policyDoc, err := f5xc.GetSecretPolicyDocument(ctx, client, "ves-io-allow-volterra", "shared")
	if err != nil {
		t.Errorf("GetSecretPolicyDocument raised an unexpected error: %v", err)
	}
	if policyDoc == nil {
		t.Errorf("GetSecretPolicyDocument returned nil")
	}
}
