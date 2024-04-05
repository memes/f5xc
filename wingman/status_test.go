package wingman_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/memes/f5xc/wingman"
)

// Mock wingman /status handler. Requests received where the current time is before the specified readyAfter value will
// return an "INITIALIZING" status, requests received after readyAfter value will return "READY".
func testWingmanStatusHandler(t *testing.T, readyAfter time.Time) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if time.Now().After(readyAfter) {
			if _, err := w.Write([]byte("READY")); err != nil {
				t.Errorf("unexpected error writing READY response: %v", err)
			}
		} else {
			if _, err := w.Write([]byte("INITIALIZING")); err != nil {
				t.Errorf("unexpected error writing INITIALIZING response: %v", err)
			}
		}
	})
}

// Verify the WaitForReady function behaves as expected.
// NOTE: This test will be skipped when used with short flag `go test -v ./...`.
func TestWaitForReady(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping WaitForReady test because of short flag")
	}
	tests := []struct {
		name             string
		timeout          time.Duration
		serverStartDelay time.Duration
		expectedError    error
	}{
		{
			name: "default",
		},
		{
			name:          "timeout",
			timeout:       1 * time.Second,
			expectedError: wingman.ErrNotReady,
		},
		{
			name:             "delayed-start",
			timeout:          60 * time.Second,
			serverStartDelay: 20 * time.Second,
		},
	}
	t.Parallel()
	// httptest server will only return a client when started, so use the default client
	client := http.DefaultClient
	t.Cleanup(client.CloseIdleConnections)
	for _, test := range tests {
		tst := test
		t.Run(tst.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewUnstartedServer(testWingmanStatusHandler(t, time.Now().Add(10*time.Second)))
			t.Cleanup(server.Close)
			go func() {
				if tst.serverStartDelay != 0 {
					time.Sleep(tst.serverStartDelay)
				}
				server.Start()
			}()
			var ctx context.Context
			var cancel context.CancelFunc
			if tst.timeout != 0 {
				ctx, cancel = context.WithTimeout(context.Background(), tst.timeout)
			} else {
				ctx = context.Background()
				cancel = func() {}
			}
			defer cancel()
			// The server may not be started yet leaving server.URL will be empty, so generate the URL from it's listener
			url := "http://" + server.Listener.Addr().String()
			err := wingman.WaitForReady(ctx, client, url, 5*time.Second)
			switch {
			case tst.expectedError == nil && err != nil:
				t.Errorf("WaitForReady raised an unexpected error: %v", err)
			case tst.expectedError != nil && !errors.Is(err, tst.expectedError):
				t.Errorf("Expected WaitForReady to raise %v, got %v", tst.expectedError, err)
			}
		})
	}
}

func ExampleDefaultWaitForReady() {
	// Wait up to 10 seconds for Wingman to be ready - for production-ready implementations this should be much
	// higher to give wingman enough time to initialize and be ready to unseal secrets.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := wingman.DefaultWaitForReady(ctx); err != nil {
		fmt.Printf("Failure waiting for Wingman to be ready: %v", err)
	}
	// Output: Failure waiting for Wingman to be ready: wingman is not ready
}
