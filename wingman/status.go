// Package wingman provides high-level functions that can interact with an F5XC wingman container.
//
// The package provides [DefaultUnseal] and [DefaultUnsealEncoded] that receive a byte array containing . E.g. if you
// used vesctl to blindfold a file and
package wingman

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// DefaultWingmanURL defines the default URL base to use when accessing Wingman deployed as a sidecar on vk8s.
const DefaultWingmanURL = "http://localhost:8070"

// StatusEndpoint defines the Wingman REST API status endpoint.
const StatusEndpoint = "/status"

// ErrNotReady indicates that Wingman service has not reported as ready to receive requests before the context was canceled.
var ErrNotReady = errors.New("wingman is not ready")

// WaitForReady will poll the Wingman status endpoint and return nil when the response has a 200 status code and a body
// that is READY.
//
// All transient connection errors, HTTP errors, and other status codes are silently ignored and polling
// will continue. An error will only be returned if a valid [http.Request] cannot be created from the endpoint, or if the
// context is canceled or completed before a successful response is received the error will be [ErrNotReady].
//
// It is the callers responsibility to ensure that the http.Client and endpoint are suitable for communicating with
// Wingman; the function [DefaultWaitForReady] can be used if Wingman is deployed as a sidecar listening on default port.
func WaitForReady(ctx context.Context, client *http.Client, endpoint string, sleepBetweenAttempts time.Duration) error {
	logger := slog.With("endpoint", endpoint, "sleepBetweenAttempts", sleepBetweenAttempts)
	logger.Debug("Waiting for wingman to be ready")
	timer := time.NewTimer(1 * time.Millisecond)
	for {
		select {
		case <-ctx.Done():
			logger.Debug("Context has been canceled")
			if !timer.Stop() {
				logger.Debug("Clearing timer channel")
				<-timer.C
			}
			return ErrNotReady
		case <-timer.C:
			logger.Debug("Checking wingman status")
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			if err != nil {
				return fmt.Errorf("failed to create status request: %w", err)
			}
			resp, err := client.Do(req)
			if err != nil {
				logger.Debug("failure during status request, ignoring", "err", err)
				timer.Reset(sleepBetweenAttempts)
				break
			}
			logger := logger.With("statusCode", resp.StatusCode)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				logger.Debug("failed to read wingman status response body, ignoring", "err", err)
			} else {
				logger := logger.With("body", body)
				logger.Debug("Wingman response received")
				if resp.StatusCode == 200 && bytes.Equal(body, []byte("READY")) {
					logger.Debug("Wingman status is READY")
					return nil
				}
				logger.Debug("Wingman is not ready, sleeping")
				timer.Reset(sleepBetweenAttempts)
			}
		}
	}
}

// DefaultWaitForReady will poll the default Wingman sidecar status endpoint every 10 seconds and will return nil once
// the response has a 200 status code and a body that is READY.
//
// All transient connection errors, HTTP errors, and other status codes are silently ignored and polling
// will continue. An error will only be returned if a valid [http.Request] cannot be created from the endpoint, or if the
// context is canceled or completed before a successful response is received the error will be [ErrNotReady].
func DefaultWaitForReady(ctx context.Context) error {
	return WaitForReady(ctx, http.DefaultClient, DefaultWingmanURL+StatusEndpoint, 10*time.Second)
}
