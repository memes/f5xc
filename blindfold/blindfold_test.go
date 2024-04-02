package blindfold_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/memes/f5xc"
	"github.com/memes/f5xc/blindfold"
)

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
			ctx, cancel := context.WithTimeout(context.TODO(), 2*time.Second)
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

// Verify that Blindfold can retrieve the standard 'Allow Volterra' policy that should be present in every tenant, the
// current authenticated user's public key, and use these with a local copy of vesctl to seal a secret.
// NOTE: This test will be skipped if Volterra authentication values are missing from the environment.
func TestBlindfold(t *testing.T) {
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
		f5xc.WithP12Certificate(p12Path, p12Passphrase),
	)
	if err != nil {
		t.Errorf("Unexpected error raised by NewClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3600*time.Second)
	defer cancel()
	publicKey, err := f5xc.GetPublicKey(ctx, client, nil)
	if err != nil {
		t.Errorf("GetPublicKey raised an unexpected error: %v", err)
	}
	if publicKey == nil {
		t.Errorf("GetPublicKey returned nil")
	}
	policyDoc, err := f5xc.GetSecretPolicyDocument(ctx, client, "ves-io-allow-volterra", "shared")
	if err != nil {
		t.Errorf("GetPolicyDocument raised an unexpected error: %v", err)
	}
	if policyDoc == nil {
		t.Errorf("GetPolicyDocument returned nil")
	}
	sealed, err := blindfold.Blindfold(ctx, blindfold.VesctlExecutable, plaintext, publicKey, policyDoc)
	if err != nil {
		t.Errorf("Blindfold raised an unexpected error: %v", err)
	}
	if sealed == nil {
		t.Errorf("Blindfold returned nil")
	}
}
