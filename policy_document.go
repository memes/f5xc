package f5xc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
)

// The partial URL to fetch PolicyDocument from F5 Distributed Cloud.
const SecretPolicyDocumentURL = "/api/secret_management/namespaces/%s/secret_policys/%s/get_policy_document"

// Represents a single SecretPolicyRule as described at https://docs.cloud.f5.com/docs/api/secret-policy-rule.
type SecretPolicyRule struct {
	Action            string             `json:"action" yaml:"action"`
	ClientName        string             `json:"client_name,omitempty" yaml:"clientName,omitempty"`
	ClientNameMatcher *MatcherType       `json:"client_name_matcher,omitempty" yaml:"clientNameMatcher,omitempty"`
	ClientSelector    *LabelSelectorType `json:"client_selector,omitempty" yaml:"clientSelector,omitempty"`
}

// Represents the specifications of a secret policy as described at
// https://docs.cloud.f5.com/docs/api/secret-management#operation/ves.io.schema.secret_management.CustomAPI.GetPolicyDocument.
type SecretPolicyInfo struct {
	Algo  string             `json:"algo" yaml:"algo"`
	Rules []SecretPolicyRule `json:"rules" yaml:"rules"`
}

// Represents the complete specification of a secret policy as described at
// https://docs.cloud.f5.com/docs/api/secret-management#operation/ves.io.schema.secret_management.CustomAPI.GetPolicyDocument.
type SecretPolicyDocument struct {
	*Metadata
	PolicyID   string           `json:"policy_id" yaml:"policyId"`
	PolicyInfo SecretPolicyInfo `json:"policy_info" yaml:"policyInfo"`
}

// Returns a SecretPolicyDocument from the F5 Distributed Cloud API endpoint for Secrets Management, or an error.
func GetSecretPolicyDocument(ctx context.Context, client *http.Client, name, namespace string) (*SecretPolicyDocument, error) {
	logger := slog.With("name", name, "namespace", namespace)
	logger.Debug("Retrieving Policy Document")
	url := fmt.Sprintf(SecretPolicyDocumentURL, namespace, name)
	logger.Debug("Generated API URL", "url", url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for PolicyDocument: %w", err)
	}
	return EnvelopeAPICall[SecretPolicyDocument](client, req)
}
