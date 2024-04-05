package f5xc

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

var (
	// Failed to add CA certificate to pool.
	ErrFailedToAppendCACert = errors.New("failed to append CA cert to CA pool")
	// Could not create a new custom http.Client because authentication was not provided.
	ErrMissingAuthentication = errors.New("a client certificate or API token must be provided")
	// Endpoint URL could not be parsed from the string provided, or the schema was invalid.
	ErrInvalidEndpointURL = errors.New("failed to parse API endpoint URL")
	// Endpoint URL was not provided to NewClient.
	ErrMissingURL = errors.New("an API URL must be provided")
	// Authentication via client certificate or API Token is not present in the request.
	ErrUnauthorized = errors.New("authentication is required")
	// Authorization failed and the client does not have permission to reach the endpoint.
	ErrForbidden = errors.New("access to endpoint is denied")
	// Returned by EnvelopeAPICall function when response status is not 200, 401 or 403.
	ErrUnexpectedHTTPStatus = errors.New("endpoint returned an unexpected status code")
)

// Defines the configuration options for an F5 XC Client.
type config struct {
	EndpointURL *url.URL
	caCertPool  *x509.CertPool
	Cert        *tls.Certificate
	AuthToken   string
}

// Defines a configuration setting function.
type Option func(*config) error

// Use the supplied endpoint URL for all requests to F5 XC when calling NewClient.
func WithAPIEndpoint(apiEndpoint string) Option {
	return func(c *config) error {
		slog.Debug("Adding API URL", "apiURL", apiEndpoint)
		baseURL, err := url.ParseRequestURI(apiEndpoint)
		switch {
		case err != nil:
			return fmt.Errorf("parsing error: %w", ErrInvalidEndpointURL)
		case baseURL.Scheme != "https":
			return fmt.Errorf("scheme must be https: %w", ErrInvalidEndpointURL)
		case baseURL.Host == "":
			return fmt.Errorf("host must be present: %w", ErrInvalidEndpointURL)
		}
		c.EndpointURL = baseURL
		return nil
	}
}

// Adds the x509 CA Certificate at the given path to the set CA certificates known
// to the system when calling NewClient.
func WithCACert(caCert string) Option {
	return func(c *config) error {
		logger := slog.With("caCert", caCert)
		logger.Debug("Adding CA certificate to pool")
		ca, err := os.ReadFile((caCert))
		if err != nil {
			return fmt.Errorf("failed to read from certificate file %s: %w", caCert, err)
		}
		if c.caCertPool == nil {
			pool, err := x509.SystemCertPool()
			if err != nil {
				return fmt.Errorf("failed to build new CA cert pool from SystemCertPool: %w", err)
			}
			c.caCertPool = pool
		}
		if ok := c.caCertPool.AppendCertsFromPEM(ca); !ok {
			return fmt.Errorf("failed to process CA cert %s: %w", caCert, ErrFailedToAppendCACert)
		}
		return nil
	}
}

// Implements an Option that sets Client authentication to use the provided
// PKCS#12 certificate, disabling token authentication.
func WithP12Certificate(path, passphrase string) Option {
	return func(c *config) error {
		logger := slog.With("path", path)
		logger.Debug("Adding PKCS#12 certificate as authenticator")
		rawData, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read from P12 file %s: %w", path, err)
		}
		key, cert, caCerts, err := pkcs12.DecodeChain(rawData, passphrase)
		if err != nil {
			return fmt.Errorf("failed to decode P12 file %s: %w", path, err)
		}
		if len(caCerts) > 0 {
			if c.caCertPool == nil {
				pool, err := x509.SystemCertPool()
				if err != nil {
					return fmt.Errorf("failed to load system CA certs as pool: %w", err)
				}
				c.caCertPool = pool
			}
			for _, caCert := range caCerts {
				c.caCertPool.AddCert(caCert)
			}
		}
		c.Cert = &tls.Certificate{
			Certificate: [][]byte{cert.Raw},
			Leaf:        cert,
			PrivateKey:  key,
		}
		c.AuthToken = ""
		return nil
	}
}

// Implements an Option that sets Client authentication to use the x509 certificate
// and key pair, disabling token authentication.
func WithCertKeyPair(certPath, keyPath string) Option {
	return func(c *config) error {
		logger := slog.With("certPath", certPath, "keyPath", keyPath)
		logger.Debug("Adding client certificate")
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return fmt.Errorf("failed to load certificate %s and key %s: %w", certPath, keyPath, err)
		}
		c.Cert = &cert
		c.AuthToken = ""
		return nil
	}
}

// Implements an option that sets client authentication to use the provided
// authentication token, disabling certificate based authentication.
func WithAuthToken(token string) Option {
	return func(c *config) error {
		slog.Debug("Adding authentication token")
		c.AuthToken = token
		c.Cert = nil
		return nil
	}
}

// The XC client may need to make changes to requests before sending to API
// endpoints.
type transport struct {
	// The encapsulated http.Transport.
	base *http.Transport
	// Optional authentication token to add.
	authToken string
	// The endpoint to substitute for all F5 XC requests.
	endpoint *url.URL
}

// Implements RoundTripper interface for F5 XC API calls; essentially it ensures that the authentication token is present
// in the request *IF* it is a non-empty string. Most consumers of the module will be using the client with a valid
// TLS certificate as identification, in which case this is essentially delegates unchanged requests to a standard library
// Transport implementation.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// All XC API requests should be set to JSON.
	req.Header.Set("Content-Type", "application/json")
	if t.authToken != "" {
		slog.Debug("Adding authToken header")
		// Brute-force approach since the XC API is expecting only oneAuthorization header and want to ensure it is the value set
		// by the client configuration.
		req.Header.Set("Authorization", "APIToken "+t.authToken)
	}
	if t.endpoint != nil && req.URL.Host != t.endpoint.Host {
		requestURL, err := t.endpoint.Parse(req.URL.RequestURI())
		if err != nil {
			return nil, fmt.Errorf("failed to parse URL from request: %w", err)
		}
		slog.Debug("Modifying request URL and host", "url", requestURL, "host", t.endpoint.Host)
		req.URL = requestURL
		req.Host = t.endpoint.Host
	}
	return t.base.RoundTrip(req) //nolint:wrapcheck // It is appropriate to return the http package error as-is
}

// Implement CloseIdleConnections to ensure that any underlying connections in base transport pool are closed as necessary.
func (t *transport) CloseIdleConnections() {
	t.base.CloseIdleConnections()
}

// Creates a new HTTP client that is pre-configured to authenticate to F5 XC endpoints.
func NewClient(options ...Option) (*http.Client, error) {
	cfg := &config{}
	for _, option := range options {
		if err := option(cfg); err != nil {
			return nil, err
		}
	}
	switch {
	case cfg.EndpointURL == nil:
		return nil, ErrMissingURL
	case cfg.Cert == nil && cfg.AuthToken == "":
		return nil, ErrMissingAuthentication
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    cfg.caCertPool,
	}
	if cfg.Cert != nil {
		tlsConfig.Certificates = []tls.Certificate{*cfg.Cert}
	}
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.TLSClientConfig = tlsConfig
	return &http.Client{
		Transport: &transport{
			base:      baseTransport,
			authToken: cfg.AuthToken,
			endpoint:  cfg.EndpointURL,
		},
	}, nil
}

// Helper method to make F5XC API requests where the response is expected to be
// in an Envelope, returning the embedded resource or an error. This function
// expects an HTTP status code of 200 as the only indicator of success; it will
// return nil if HTTP status code is 404, or one of the f5xc package errors for
// all other statuses.
func EnvelopeAPICall[T EnvelopeAllowed](client *http.Client, req *http.Request) (*T, error) {
	slog.Debug("Calling API")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failure making API call: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read API response body: %w", err)
		}
		envelope := &Envelope[T]{}
		err = json.Unmarshal(data, envelope)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
		}
		return &envelope.Data, nil
	case http.StatusUnauthorized:
		return nil, ErrUnauthorized
	case http.StatusForbidden:
		return nil, ErrForbidden
	case http.StatusNotFound:
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected HTTP status code %d: %w", resp.StatusCode, ErrUnexpectedHTTPStatus)
}
