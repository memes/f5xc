package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/memes/f5xc/wingman"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// Implements a dummy wingman endpoint for unsealing a blindfolded secret; for the purposes of testing the steps are
// de-base64 encode => rot13 => base64 encode payload for return. Any request that deviates from expected content
// structure will return 500 or 400 status.
func testWingmanUnsealHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Logf("unexpected error reading request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var payload struct {
			Location string `json:"location"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Logf("failed to unmarshal request JSON: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		scheme, b64, ok := strings.Cut(payload.Location, ":///")
		switch {
		case !ok:
			t.Logf("payload location did not match expected scheme: %s", payload.Location)
			w.WriteHeader(http.StatusBadRequest)
			return
		case scheme != "string":
			t.Logf("expected payload scheme to be 'string', got %q", scheme)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Logf("failed to decode base64 data: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// ROT13 to decode the sealed data
		for i, b := range data {
			switch {
			case b >= 'A' && b <= 'Z':
				data[i] = (b-'A'+13)%26 + 'A'
			case b >= 'a' && b <= 'z':
				data[i] = (b-'a'+13)%26 + 'a'
			}
		}
		encoder := base64.NewEncoder(base64.StdEncoding, w)
		if _, err := encoder.Write(data); err != nil {
			t.Logf("failed to write base64 data to response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := encoder.Close(); err != nil {
			t.Logf("error closing bas64 encoder: %v", err)
		}
	})
}

// Verify that the unexported process function behaves as expected.
func TestProcess(t *testing.T) {
	tmpDir := t.TempDir()
	fmt.Println(tmpDir)
	tests := []struct {
		name          string
		spec          []byte
		expected      map[string][]byte
		expectedError any
	}{
		// spell-checker: disable
		{
			name:          "empty",
			expectedError: json.SyntaxError{},
		},
		{
			name: "simple",
			spec: []byte(`{"` + tmpDir + `/simple.json":"ZnZ6Y3lyLndmYmE="}`),
			expected: map[string][]byte{
				tmpDir + "/simple.json": []byte("simple.json"),
			},
		},
		{
			name:          "invalid",
			spec:          []byte(`{"` + tmpDir + `/invalid.json":"&&&&&&&"}`),
			expectedError: wingman.ErrUnexpectedHTTPStatus,
		},
		// spell-checker: enable
	}
	t.Parallel()
	for _, test := range tests {
		tst := test
		t.Run(tst.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(testWingmanUnsealHandler(t))
			t.Cleanup(server.Close)
			client := server.Client()
			t.Cleanup(client.CloseIdleConnections)
			ctx, cancel := context.WithTimeout(context.Background(), 3600*time.Second)
			defer cancel()
			err := process(ctx, client, server.URL, tst.spec)
			switch {
			case tst.expectedError == nil && err != nil:
				t.Errorf("process raised an unexpected error: %v", err)
			case tst.expectedError != nil && !errors.As(err, &tst.expectedError):
				t.Errorf("Expected process to raise %v, got %v", tst.expectedError, err)
			default:
				for path, expected := range tst.expected {
					result, err := os.ReadFile(path)
					if err != nil {
						t.Errorf("Failed to open file: %v", err)
						break
					}
					if !bytes.Equal(expected, result) {
						t.Errorf("Expected file to contain %v, got %v", expected, result)
					}
				}
			}
		})
	}
}
