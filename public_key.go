package f5xc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
)

// PublicKeyURL defines the partial URL to fetch a PublicKey from F5 Distributed Cloud.
const PublicKeyURL = "/api/secret_management/get_public_key"

// PublicKey represents an F5XC Public Key for authenticated account, as described at
// https://docs.cloud.f5.com/docs/api/secret-management#operation/ves.io.schema.secret_management.CustomAPI.GetPublicKey.
type PublicKey struct {
	KeyVersion           int    `json:"key_version" yaml:"keyVersion"`
	ModulusBase64        string `json:"modulus_base64" yaml:"modulusBase64"`
	PublicExponentBase64 string `json:"public_exponent_base64" yaml:"publicExponentBase64"`
	Tenant               string `json:"tenant" yaml:"tenant"`
}

// GetPublicKey returns a PublicKey from the F5 Distributed Cloud API endpoint for Secrets Management, or an error.
func GetPublicKey(ctx context.Context, client *http.Client, version *int) (*PublicKey, error) {
	logger := slog.With("version", version)
	logger.Debug("Retrieving Public Key")
	url := PublicKeyURL
	if version != nil {
		url = fmt.Sprintf("%s?key_version=%d", PublicKeyURL, version)
	}
	logger.Debug("Generated API URL", "url", url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for PublicKey: %w", err)
	}
	return EnvelopeAPICall[PublicKey](client, req)
}
