// Package blindfold encapsulates the steps necessary to invoke vesctl as an external producer of a sealed secret.
package blindfold

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"os/exec"

	"github.com/memes/f5xc"
	"gopkg.in/yaml.v3"
)

// The default name to use when searching for vesctl.
const VesctlExecutable = "vesctl"

// ErrVesctl indicates that vesctl process failed or exited with status code other than 0.
var ErrVesctl = errors.New("failed to execute vesctl")

// Finds the vesctl binary matching name in system paths, or returns an error. The name parameter can be left empty to
// find vesctl using it's default name, set to a different filename to search (e.g. "vesctl.0.2.37"), or a full path to
// a known binary location.
func FindVesctl(name string) (string, error) {
	if name == "" {
		name = VesctlExecutable
	}
	slog.Debug("Looking for vesctl binary", "name", name)
	vesctl, err := exec.LookPath(name)
	if err != nil && errors.Is(err, exec.ErrDot) {
		err = nil
	}
	return vesctl, err
}

// Source for semi-random override of Volterra environment variables.
const randomStringChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345689_"

// Helper function to create a pseudo-random string of length n.
func RandomString(n int) string {
	buf := make([]byte, n)
	for i := range buf {
		//nolint:gosec // Don't need cryptographically secure pseudo random number generation
		buf[i] = randomStringChars[rand.Intn(len(randomStringChars))]
	}
	return string(buf)
}

// Execute vesctl with as much isolation as possible. We really, really don't want vesctl making API calls accidentally
// and it is expected that the consumer of this library is using this function where the environment variables include
// one or more of VES_P12_PASSWORD, VOLT_API_*, or VOLTERRA_TOKEN set to legitimate values. For that reason, vesctl will
// be launched with a set of environment variables and command line options set to dummy/empty/random values to minimize
// any accidental leak of information *except* for the parameters which are required for blindfold operation, which is
// itself an offline function.
func ExecuteVesctl(ctx context.Context, vesctl string, args []string, params map[string]string, stdOut, stdErr io.Writer) error {
	logger := slog.With("vesctl", vesctl, "args", args, "params", params)
	logger.Debug("Attempting to execute vesctl")

	emptyFile, err := os.CreateTemp("", "vesctl")
	if err != nil {
		return fmt.Errorf("failed to create empty file: %w", err)
	}
	emptyInputFile := emptyFile.Name()
	defer os.Remove(emptyInputFile)
	if err := emptyFile.Close(); err != nil {
		return fmt.Errorf("failed to close empty file: %w", err)
	}

	// Explicitly set file-sourcing parameters to the empty file, and set API URLs to a RFC2066 host that should not
	// resolve, then merge in any parameters provided by the caller.
	parameters := map[string]string{
		"--p12-bundle":  emptyInputFile,
		"--cert":        emptyInputFile,
		"--key":         emptyInputFile,
		"--config":      emptyInputFile,
		"--server-urls": "https://f5xc.invalid/api",
	}

	//nolint:godox // todo is needed here for issue tracking
	// TODO @memes - add logic to limit the args and/or param keys that are permitted.
	for k, v := range params {
		parameters[k] = v
	}
	finalArguments := args
	for k, v := range parameters {
		finalArguments = append(finalArguments, k, v)
	}
	cmd := exec.CommandContext(ctx, vesctl, finalArguments...)
	cmd.Env = []string{
		"VES_P12_PASSWORD=" + RandomString(16),
		"VOLT_API_P12_FILE=" + emptyInputFile,
		"VOLT_API_CERT=" + emptyInputFile,
		"VOLT_API_KEY=" + emptyInputFile,
		"VOLT_API_URL=https://f5xc.invalid/api",
		"VOLTERRA_TOKEN=" + RandomString(16),
	}
	cmd.Stdin = nil
	cmd.Stdout = stdOut
	cmd.Stderr = stdErr
	slog.Debug("About to execute vesctl", "finalArguments", finalArguments)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failure while executing vesctl: %w: %w", err, ErrVesctl)
	}

	return nil
}

// Executes vesctl to blindfold the supplied plaintext using the supplied PublicKey and PolicyDocument, returning the
// Base64 encoded sealed data. The function will write and cleanup temporary files to use as inputs to vesctl, and will
// create an execution environment that overrides the values of common VOLT_*, VES_*, and VOLTERRA_* with invalid values
// to avoid leaking data.
func Blindfold(ctx context.Context, vesctl string, plaintext []byte, pubKey *f5xc.PublicKey, policyDoc *f5xc.SecretPolicyDocument) ([]byte, error) {
	logger := slog.With("vesctl", vesctl)
	logger.Debug("Preparing to blindfold")
	vesctlPath, err := FindVesctl(vesctl)
	if err != nil {
		return nil, fmt.Errorf("failed to locate vesctl(%q) %w", vesctl, err)
	}

	// Vesctl requires that YAML file of the public key and policy document, and a file containing the plaintext
	// data are present on an available filesystem. Create a temporary directory and write the files; the temp dir
	// will be cleaned up when the function exits. Any error will cause the function to exit even if the underlying
	// condition is recoverable.
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	pubKeyFile, err := createTempYAMLEnvelope[f5xc.PublicKey](*pubKey, tmpDir)
	if err != nil {
		return nil, fmt.Errorf("failed to write PublicKey envelope file: %w", err)
	}
	policyDocumentFile, err := createTempYAMLEnvelope[f5xc.SecretPolicyDocument](*policyDoc, tmpDir)
	if err != nil {
		return nil, fmt.Errorf("failed to write PolicyDocument envelope file: %w", err)
	}
	plaintextFile, err := os.CreateTemp(tmpDir, "blindfold")
	if err != nil {
		return nil, fmt.Errorf("failed to create plaintext file: %w", err)
	}
	if _, err = plaintextFile.Write(plaintext); err != nil {
		_ = plaintextFile.Close()
		return nil, fmt.Errorf("failed to write plaintext file: %w", err)
	}
	if err = plaintextFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close plaintext file: %w", err)
	}

	var buf bytes.Buffer
	args := []string{
		"request", "secrets", "encrypt", plaintextFile.Name(),
	}
	params := map[string]string{
		"--public-key":      pubKeyFile,
		"--policy-document": policyDocumentFile,
	}
	if err := ExecuteVesctl(ctx, vesctlPath, args, params, &buf, nil); err != nil {
		return nil, err
	}

	// The output from vesctl will have a leading header line which should be ignored; scan over the output and return
	// the bytes from the second line only.
	//nolint:godox // todo is needed here for issue tracking
	// TODO @memes - potential future issue if/when vesctl output changes
	var data []byte
	lineCount := 0
	scanner := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	for scanner.Scan() {
		if lineCount == 1 {
			data = scanner.Bytes()
			break
		}
		lineCount++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan vesctl output: %w", err)
	}
	return data, nil
}

// Helper function to marshal an object to an Envelope and write to a temp file.
// It is the callers responsibility to clean-up the temporary file.
func createTempYAMLEnvelope[T f5xc.EnvelopeAllowed](obj T, tmpDir string) (string, error) {
	f, err := os.CreateTemp(tmpDir, "blindfold")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer f.Close()
	data, err := yaml.Marshal(f5xc.Envelope[T]{Data: obj})
	if err != nil {
		return "", fmt.Errorf("failed to marshal to YAML: %w", err)
	}
	if _, err = f.Write(data); err != nil {
		return "", fmt.Errorf("failed to write data to file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("failed to close file: %w", err)
	}
	return f.Name(), nil
}
