package handlers

import (
	"encoding/json"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type EnvVarSecretHandler struct {
	BasePolicyHandler
}

const (
	RuleEnvVarSecret = "envVarSecrets" // #nosec G101 - This is a rule identifier, not a secret
)

func NewEnvVarSecretHandler() *EnvVarSecretHandler {
	return &EnvVarSecretHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported: false,
			SupportedOps: map[string]bool{
				nvdata.CriteriaOpEqual: true,
			},
			Name:   share.ExtractModuleName(share.PolicyEnvSecretScannerURI),
			Module: share.PolicyEnvSecretScannerURI,
		},
	}
}

// BuildPolicySettings builds settings for a single criterion.
func (h *EnvVarSecretHandler) BuildPolicySettings(criterion *nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	return h.BuildGroupedPolicySettings([]*nvapis.RESTAdmRuleCriterion{criterion})
}

// BuildGroupedPolicySettings builds settings from multiple criteria that map to the same module.
func (h *EnvVarSecretHandler) BuildGroupedPolicySettings(
	_ []*nvapis.RESTAdmRuleCriterion,
) ([]byte, error) {
	settingsBytes, err := json.Marshal(map[string]string{})
	if err != nil {
		return nil, err
	}
	return settingsBytes, nil
}
