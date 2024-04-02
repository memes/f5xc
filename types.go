package f5xc

// Represents the metadata associated with F5XC data types.
type Metadata struct {
	Name      string `json:"name,omitempty" yaml:"name,omitempty"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Tenant    string `json:"tenant,omitempty" yaml:"tenant,omitempty"`
}

// Represents a matcher that is commonly used to apply a set of declarations to a set of resources that satisfy one of
// the requirements.
type MatcherType struct {
	ExactValues  []string `json:"exact_values" yaml:"exactValues"`
	RegexValues  []string `json:"regex_values" yaml:"regexValues"`
	Transformers []string `json:"transformers" yaml:"transformers"`
}

// Represents a matcher that selects resources based on Metadata label expressions, similar to Kubernetes.
type LabelSelectorType struct {
	Expressions []string `json:"expressions" yaml:"expressions"`
}

// Defines a type constraint for resources known to be encapsulated in an Envelope when requested from F5XC endpoints.
type EnvelopeAllowed interface {
	PublicKey | SecretPolicyDocument
}

// Many F5XC endpoints encapsulate the requested information in an envelope with a data field contains the requested
// resource.
type Envelope[T EnvelopeAllowed] struct {
	Data T `json:"data" yaml:"data"`
}
