package share

import (
	nvapis "github.com/neuvector/neuvector/controller/api"
)

// ConversionConfig holds configuration for the conversion process.
type ConversionConfig struct {
	OutputFile      string
	PolicyServer    string
	Mode            string
	BackgroundAudit bool
	ShowSummary     bool
}

// PolicyHandler defines the interface that each policy handler must implement
// This interface is placed in share to avoid circular dependencies between packages.
type PolicyHandler interface {
	// Validate validates a criterion and returns an error if invalid
	Validate(criterion *nvapis.RESTAdmRuleCriterion) error

	// IsUnsupported returns true if this criterion is not supported
	IsUnsupported() bool

	// GetSupportedOps returns a map of supported operators for this criterion
	GetSupportedOps() map[string]bool

	// GetModule returns the Kubewarden policy module for this criterion
	GetModule() string

	// GetApplicableResource returns the resources that the policy is applicable to (e.g. "pvc", "workload")
	GetApplicableResource() string

	// BuildPolicySettings builds the policy settings for one criterion or multiple criteria that map to the same module
	BuildPolicySettings(criteria []*nvapis.RESTAdmRuleCriterion) ([]byte, error)
}
