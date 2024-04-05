package wingman

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// The Wingman REST unseal endpoint.
const UnsealEndpoint = "/secret/unseal"

// ErrDeniedByPolicy is returned by unseal functions when access is denied by security policy used during seal.
var ErrDeniedByPolicy = errors.New("denied by security policy")

// ErrUnexpectedHTTPStatus is returned by unseal functions when wingman response status is not 200, 403 or 503.
var ErrUnexpectedHTTPStatus = errors.New("wingman returned an unexpected status code")

// Unseal a byte slice of blindfold data, and returns a byte array of the unsealed data.
//
// The sealed bytes will be base64 encoded before sending request; if you have a base64 encoded blindfold secret, as
// generated directly from vesctl say, use [UnsealEncoded] function to avoid double-encoding of the sealed data.
//
// It is the callers responsibility to ensure that the http.Client and endpoint are suitable for communicating with
// Wingman; the function [DefaultUnseal] can be used if Wingman is deployed as a sidecar listening on default port.
func Unseal(ctx context.Context, client *http.Client, endpoint string, sealed []byte) ([]byte, error) {
	slog.Debug("Building unseal payload from unencoded source")
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	if _, err := encoder.Write(sealed); err != nil {
		return nil, fmt.Errorf("failed to base64 encode data: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("error closing bas64 encoder: %w", err)
	}
	return UnsealEncoded(ctx, client, endpoint, buf.Bytes())
}

// Unseal a byte slice of base64 encoded blindfold data, and returns a byte array of the unsealed data.
//
// The sealed bytes will be embedded in the request as-is; use [Unseal] if the sealed bytes must be base64 encoded as
// required by Wingman's unseal endpoint.
//
// It is the callers responsibility to ensure that the http.Client and endpoint are suitable for communicating with
// Wingman; the function [DefaultUnsealEncoded] can be used if Wingman is deployed as a sidecar listening on default port.
func UnsealEncoded(ctx context.Context, client *http.Client, endpoint string, sealed []byte) ([]byte, error) {
	logger := slog.With("endpoint", endpoint)
	logger.Debug("Preparing unseal request from encoded source")
	var buf bytes.Buffer
	buf.WriteString(`{"type":"blindfold","location":"string:///`)
	buf.Write(sealed)
	buf.WriteString(`"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for unseal: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	logger.Debug("Sending unseal request")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failure during unseal request: %w", err)
	}
	slog.Debug("Processing unseal response", "statusCode", resp.StatusCode)
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read wingman response body: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		result := make([]byte, base64.StdEncoding.DecodedLen(len(respBody)))
		resultLen, err := base64.StdEncoding.Decode(result, respBody)
		if err != nil {
			return nil, fmt.Errorf("failed to decode response body: %w", err)
		}
		return result[:resultLen], nil
	case http.StatusForbidden:
		return nil, ErrDeniedByPolicy
	case http.StatusServiceUnavailable:
		return nil, fmt.Errorf("%s: %w", string(respBody), ErrNotReady)
	}
	return nil, fmt.Errorf("unexpected HTTP status code %d: message %q: %w", resp.StatusCode, string(respBody), ErrUnexpectedHTTPStatus)
}

// Unseal a byte slice of blindfold data, and returns a byte array of the unsealed data, using a sidecar Wingman listening
// on HTTP port 8070.
//
// The sealed bytes will be base64 encoded before sending request; if you have a base64 encoded blindfold secret, as
// output from vesctl say, use [DefaultUnsealEncoded] function to avoid double-encoding of the sealed data.
func DefaultUnseal(ctx context.Context, sealed []byte) ([]byte, error) {
	return Unseal(ctx, http.DefaultClient, DefaultWingmanURL+UnsealEndpoint, sealed)
}

// Unseal a byte slice of base64 encoded blindfold data, and returns a byte array of the unsealed data, using a sidecar
// Wingman listening on HTTP port 8070.
//
// The sealed bytes will be embedded in the request as-is; use [DefaultUnseal] if the sealed bytes must be base64 encoded
// as required by Wingman's unseal endpoint.
func DefaultUnsealEncoded(ctx context.Context, sealed []byte) ([]byte, error) {
	return UnsealEncoded(ctx, http.DefaultClient, DefaultWingmanURL+UnsealEndpoint, sealed)
}
