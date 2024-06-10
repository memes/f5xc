package wingman_test

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

// Verify that Unseal function acts as expected.
func TestUnseal(t *testing.T) {
	tests := []struct {
		name          string
		sealed        []byte
		expected      []byte
		expectedError error
	}{
		// spell-checker: disable
		{
			name: "empty",
		},
		{
			name:     "valid",
			sealed:   []byte("Guvf vf n grfg"),
			expected: []byte("This is a test"),
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
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result, err := wingman.Unseal(ctx, client, server.URL, tst.sealed)
			switch {
			case tst.expectedError == nil && err != nil:
				t.Errorf("Unseal raised an unexpected error: %v", err)
			case tst.expectedError != nil && !errors.Is(err, tst.expectedError):
				t.Errorf("Expected Unseal to raise %v, got %v", tst.expectedError, err)
			case !bytes.Equal(tst.expected, result):
				t.Errorf("Expected %q, got %q", tst.expected, result)
			}
		})
	}
}

// Verify the UnsealEncoded function acts as expected.
func TestUnsealEncoded(t *testing.T) {
	tests := []struct {
		name          string
		sealed        []byte
		expected      []byte
		expectedError error
	}{
		// spell-checker: disable
		{
			name: "empty",
		},
		{
			name:     "valid",
			sealed:   []byte("R3V2ZiB2ZiBuIGdyZmc="),
			expected: []byte("This is a test"),
		},
		{
			name:          "invalid",
			sealed:        []byte("^^^^^^"),
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
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result, err := wingman.UnsealEncoded(ctx, client, server.URL, tst.sealed)
			switch {
			case tst.expectedError == nil && err != nil:
				t.Errorf("Unseal raised an unexpected error: %v", err)
			case tst.expectedError != nil && !errors.Is(err, tst.expectedError):
				t.Errorf("Expected Unseal to raise %v, got %v", tst.expectedError, err)
			case !bytes.Equal(tst.expected, result):
				t.Errorf("Expected %q, got %q", tst.expected, result)
			}
		})
	}
}

func ExampleDefaultUnseal() {
	// Allow wingman up to 10 seconds to try to unseal a secret
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	secretData, err := wingman.DefaultUnseal(ctx, []byte("Guvf vf n grfg")) // spell-checker: disable-line
	if err != nil {
		fmt.Printf("Failure unsealing blindfold secret: %v", err)
		return
	}
	// Use the unsealed secret data
	fmt.Printf("secretData is %v", secretData)
	// Output: Failure unsealing blindfold secret: failure during unseal request: Post "http://localhost:8070/secret/unseal": dial tcp 127.0.0.1:8070: connect: connection refused
}

func ExampleDefaultUnseal_file() {
	// Read the sealed file into a byte array
	sealed, err := os.ReadFile("testdata/blindfold.raw")
	if err != nil {
		fmt.Printf("failed to open blindfold file: %v", err)
		return
	}

	// Allow wingman up to 10 seconds to try to unseal a secret
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	secretData, err := wingman.DefaultUnseal(ctx, sealed)
	if err != nil {
		fmt.Printf("Failure unsealing blindfold secret: %v", err)
		return
	}
	// Use the unsealed secret data
	fmt.Printf("secretData is %v", secretData)
	// Output: Failure unsealing blindfold secret: failure during unseal request: Post "http://localhost:8070/secret/unseal": dial tcp 127.0.0.1:8070: connect: connection refused
}

func ExampleDefaultUnsealEncoded() {
	// Allow wingman up to 10 seconds to try to unseal a secret
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	secretData, err := wingman.DefaultUnsealEncoded(ctx, []byte("R3V2ZiB2ZiBuIGdyZmc="))
	if err != nil {
		fmt.Printf("Failure unsealing blindfold secret: %v", err)
		return
	}
	// Use the unsealed secret data
	fmt.Printf("secretData is %v", secretData)
	// Output: Failure unsealing blindfold secret: failure during unseal request: Post "http://localhost:8070/secret/unseal": dial tcp 127.0.0.1:8070: connect: connection refused
}

func ExampleDefaultUnsealEncoded_file() {
	// Read the sealed file into a byte array
	sealed, err := os.ReadFile("testdata/blindfold.b64")
	if err != nil {
		fmt.Printf("failed to open blindfold file: %v", err)
		return
	}

	// Allow wingman up to 10 seconds to try to unseal a secret
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	secretData, err := wingman.DefaultUnsealEncoded(ctx, sealed)
	if err != nil {
		fmt.Printf("Failure unsealing blindfold secret: %v", err)
		return
	}
	// Use the unsealed secret data
	fmt.Printf("secretData is %v", secretData)
	// Output: Failure unsealing blindfold secret: failure during unseal request: Post "http://localhost:8070/secret/unseal": dial tcp 127.0.0.1:8070: connect: connection refused
}
