package f5xc_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/memes/f5xc"
)

// Verify that GetPublicKey can retrieve a user's Public Key.
// NOTE: This test will be skipped if Volterra authentication values are missing from the environment.
func TestGetPublicKey(t *testing.T) {
	t.Parallel()
	p12Path := os.Getenv("VOLT_API_P12_FILE")
	p12Passphrase := os.Getenv("VES_P12_PASSWORD")
	apiURL := os.Getenv("VOLT_API_URL")
	if p12Path == "" || p12Passphrase == "" || apiURL == "" {
		t.Skip("Required environment variables are not set")
	}
	client, err := f5xc.NewClient(
		f5xc.WithAPIEndpoint(apiURL),
		f5xc.WithP12CertificateFile(p12Path, p12Passphrase),
	)
	if err != nil {
		t.Errorf("Unexpected error raised by NewClient: %v", err)
	}
	t.Cleanup(client.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	publicKey, err := f5xc.GetPublicKey(ctx, client, nil)
	if err != nil {
		t.Errorf("GetPublicKey raised an unexpected error: %v", err)
	}
	if publicKey == nil {
		t.Errorf("GetPublicKey returned nil")
	}
}
