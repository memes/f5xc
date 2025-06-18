package blindfold_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/memes/f5xc"
	"github.com/memes/f5xc/blindfold"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// Verify that the FindVesctl function works as expected.
// NOTE: Vesctl must be accessible on a system path for the positive-check to succeed.
func TestFindVesctl(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		vesctl        string
		expectedError error
	}{
		{
			name: "default",
		},
		{
			name:          "invalid-name",
			vesctl:        blindfold.RandomString(8),
			expectedError: exec.ErrNotFound,
		},
	}
	for _, test := range tests {
		tst := test
		t.Run(tst.name, func(t *testing.T) {
			t.Parallel()
			result, err := blindfold.FindVesctl(tst.vesctl)
			switch {
			case tst.expectedError == nil && err != nil:
				t.Errorf("FindVesctl raised an unexpected error: %v", err)
			case tst.expectedError != nil && !errors.Is(err, tst.expectedError):
				t.Errorf("Expected FindVesctl to raise %v, got %v", tst.expectedError, err)
			case err == nil && result == "":
				t.Errorf("Expected result not to be empty")
			}
		})
	}
}

// Verify that ExecuteVesctl functions correctly given a set of arguments.
func TestExecuteVesctl(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		args          []string
		params        map[string]string
		regex         *regexp.Regexp
		expectedError error
	}{
		{
			name: "default",
		},
		{
			name:  "version",
			args:  []string{"version"},
			regex: regexp.MustCompile("^branch: (?:[0-9]+-){2}[0-9]+"),
		},
		{
			name:          "invalid",
			args:          []string{"invalid"},
			regex:         regexp.MustCompile(`unknown command "invalid"`),
			expectedError: blindfold.ErrVesctl,
		},
	}
	vesctl, err := blindfold.FindVesctl("")
	if err != nil {
		t.Errorf("failed to find a vesctl in path: %v", err)
	}
	for _, test := range tests {
		tst := test
		t.Run(tst.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var buf bytes.Buffer
			err := blindfold.ExecuteVesctl(ctx, vesctl, tst.args, tst.params, &buf, &buf)
			output := buf.Bytes()
			switch {
			case tst.expectedError == nil && err != nil:
				t.Errorf("ExecuteVesctl raised an unexpected error: %v", err)
			case tst.expectedError != nil && !errors.Is(err, tst.expectedError):
				t.Errorf("Expected ExecuteVesctl to raise %v, got %v", tst.expectedError, err)
			case tst.regex != nil && !tst.regex.Match(output):
				t.Errorf("Expected combined output to match %s, got %s", tst.regex.String(), output)
			}
		})
	}
}

// Helper to return a PublicKey from F5XC API.
func testGetPublicKey(t *testing.T, client *http.Client) *f5xc.PublicKey {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3600*time.Second)
	defer cancel()
	publicKey, err := f5xc.GetPublicKey(ctx, client, nil)
	if err != nil {
		t.Errorf("GetPublicKey raised an unexpected error: %v", err)
	}
	if publicKey == nil {
		t.Errorf("GetPublicKey returned nil")
	}
	return publicKey
}

// Helper to return a PublicKey from F5XC API.
func testGetPolicyDoc(t *testing.T, client *http.Client) *f5xc.SecretPolicyDocument {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3600*time.Second)
	defer cancel()
	policyDoc, err := f5xc.GetSecretPolicyDocument(ctx, client, "ves-io-allow-volterra", "shared")
	if err != nil {
		t.Errorf("GetSecretPolicyDocument raised an unexpected error: %v", err)
	}
	if policyDoc == nil {
		t.Errorf("GetSecretPolicyDocument returned nil")
	}
	return policyDoc
}

// Verify that Blindfold can retrieve the standard 'Allow Volterra' policy that should be present in every tenant, the
// current authenticated user's public key, and use these with a local copy of vesctl to seal a secret byte array.
// NOTE: This test will be skipped if Volterra authentication values are missing from the environment.
func TestSeal(t *testing.T) {
	t.Parallel()
	p12Path := os.Getenv("VOLT_API_P12_FILE")
	p12Passphrase := os.Getenv("VES_P12_PASSWORD")
	apiURL := os.Getenv("VOLT_API_URL")
	plaintext := []byte("This is a plaintext document to be blindfolded")
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
	publicKey := testGetPublicKey(t, client)
	policyDoc := testGetPolicyDoc(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sealed, err := blindfold.Seal(ctx, blindfold.VesctlExecutable, plaintext, publicKey, policyDoc)
	if err != nil {
		t.Errorf("Blindfold raised an unexpected error: %v", err)
	}
	if sealed == nil {
		t.Errorf("Blindfold returned nil")
	}
}

// Helper function to create a temporary plaintext file.
func testMakeTempPlaintextFile(t *testing.T, tmpDir string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp(tmpDir, "plaintext")
	if err != nil {
		t.Errorf("failed to create temporary plaintext file: %v", err)
	}
	defer func() {
		if err = tmpFile.Close(); err != nil {
			t.Logf("Failed to close temporary file: %v", err)
		}
	}()
	if _, err = tmpFile.Write([]byte("This is a plaintext document to be blindfolded")); err != nil {
		t.Errorf("failed to write data to plaintext file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Errorf("failed to close plaintext file: %v", err)
	}
	return tmpFile.Name()
}

// Verify that SealFile can retrieve the standard 'Allow Volterra' policy that should be present in every tenant, the
// current authenticated user's public key, and use these with a local copy of vesctl to seal a secret from file path.
// NOTE: This test will be skipped if Volterra authentication values are missing from the environment.
func TestSealFile(t *testing.T) {
	t.Parallel()
	p12Path := os.Getenv("VOLT_API_P12_FILE")
	p12Passphrase := os.Getenv("VES_P12_PASSWORD")
	apiURL := os.Getenv("VOLT_API_URL")
	if p12Path == "" || p12Passphrase == "" || apiURL == "" {
		t.Skip("Required environment variables are not set")
	}
	tmpDir := t.TempDir()
	tests := []struct {
		name          string
		path          string
		expectedError error
	}{
		{
			name:          "empty",
			expectedError: blindfold.ErrVesctl,
		},
		{
			name:          "invalid",
			path:          "path/does/not/exist",
			expectedError: blindfold.ErrVesctl,
		},
		{
			name: "valid",
			path: testMakeTempPlaintextFile(t, tmpDir),
		},
	}
	client, err := f5xc.NewClient(
		f5xc.WithAPIEndpoint(apiURL),
		f5xc.WithP12CertificateFile(p12Path, p12Passphrase),
	)
	if err != nil {
		t.Errorf("Unexpected error raised by NewClient: %v", err)
	}
	t.Cleanup(client.CloseIdleConnections)
	publicKey := testGetPublicKey(t, client)
	policyDoc := testGetPolicyDoc(t, client)
	for _, test := range tests {
		tst := test
		t.Run(tst.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 3600*time.Second)
			defer cancel()
			sealed, err := blindfold.SealFile(ctx, blindfold.VesctlExecutable, tst.path, publicKey, policyDoc)
			switch {
			case tst.expectedError == nil && err != nil:
				t.Errorf("BlindfoldFile raised an unexpected error: %v", err)
			case tst.expectedError != nil && !errors.Is(err, tst.expectedError):
				t.Errorf("Expected BlindfoldFile to raise %v, got %v", tst.expectedError, err)
			case err == nil && sealed == nil:
				t.Errorf("Expected sealed byte array to not to be nil")
			case err == nil && len(sealed) == 0:
				t.Errorf("Expected sealed byte array to not be empty")
			}
		})
	}
}
