// Unseal is a utility that will read a JSON input of blindfold data, send each embedded data value to a Wingman
// endpoint to be unsealed, writing the unsealed data to the filepath given as a key.
//
// Usage:
//
//	unseal FILE [...FILE]
//
// where FILE is a JSON document containing a map of files to be written to base64 encoded sealed data.
//
// Example JSON: This will lead to the creation or refreshing of /var/lib/foo/bar.yaml and /etc/foo.ini.
//
//	{
//	  "/var/lib/foo/bar.yaml": "... base64 encoded sealed data ...",
//	  "/etc/foo.ini": "... base64 encoded sealed data ..."
//	}
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/memes/f5xc/wingman"
)

const (
	// EnvWingmanURL defines the environment variable name that can be set to override the default wingman base URL.
	EnvWingmanURL = "UNSEAL_WINGMAN_URL"
	// EnvLogLevel defines the environment variable name that can be set to change the default [log/slog] logging
	// level.
	EnvLogLevel = "UNSEAL_LOG_LEVEL"
)

func main() {
	wingmanURL := os.Getenv(EnvWingmanURL)
	if wingmanURL == "" {
		wingmanURL = wingman.DefaultWingmanURL
	}
	retCode := 0
	defer func() {
		os.Exit(retCode)
	}()
	level := slog.LevelVar{}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     &level,
	}).WithAttrs([]slog.Attr{
		{
			Key:   "wingmanURL",
			Value: slog.StringValue(wingmanURL),
		},
	})))
	if ll := os.Getenv(EnvLogLevel); ll != "" {
		if err := level.UnmarshalText([]byte(ll)); err != nil {
			slog.Warn("Failed to parse requested log level", EnvLogLevel, ll)
		}
	}

	if len(os.Args) <= 1 {
		slog.Error("No JSON files provided")
		retCode = 1
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := http.DefaultClient
	defer client.CloseIdleConnections()
	if err := wingman.WaitForReady(ctx, client, wingmanURL+wingman.StatusEndpoint, 10*time.Second); err != nil {
		slog.Error("Wingman failed to reach ready status")
		retCode = 1
		return
	}
	for _, sourceFile := range os.Args[1:] {
		logger := slog.With("sourceFile", sourceFile)
		logger.Debug("Attempting to retrieve file data")
		data, err := os.ReadFile(sourceFile)
		if err != nil {
			logger.Error("Error reading JSON specification from file", "error", err)
			retCode = 1
			return
		}
		if err := process(ctx, client, wingmanURL+wingman.UnsealEndpoint, data); err != nil {
			slog.Error("Processing failed", "error", err)
			retCode = 1
			return
		}
	}
}

func process(ctx context.Context, client *http.Client, endpoint string, payload []byte) error {
	slog.Debug("Processing JSON payload")
	var spec map[string]string
	if err := json.Unmarshal(payload, &spec); err != nil {
		return fmt.Errorf("failed to parse as JSON: %w", err)
	}
	for path, sealed := range spec {
		slog.Debug("Processing entry", "path", path, "sealed", sealed)
		unsealed, err := wingman.UnsealEncoded(ctx, client, endpoint, []byte(sealed))
		if err != nil {
			return fmt.Errorf("wingman unseal error: %w", err)
		}
		if err := os.WriteFile(path, unsealed, 0o640); err != nil { //nolint:gosec // File permissions should include group read
			return fmt.Errorf("failed to open/truncate file for writing: %w", err)
		}
	}
	return nil
}
