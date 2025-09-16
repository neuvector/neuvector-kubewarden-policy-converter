package handlers

import (
	"errors"
	"fmt"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type EnvVarSecretHandler struct {
	BasePolicyHandler
}

const (
	RuleEnvVarSecret = "envVarSecrets" // #nosec G101 - This is a rule identifier, not a secret

	PolicyEnvSecretScannerURI = "registry://ghcr.io/kubewarden/policies/env-variable-secrets-scanner:v1.0.5" // #nosec G101 - This is a policy identifier, not a secret
)

func NewEnvVarSecretHandler() *EnvVarSecretHandler {
	return &EnvVarSecretHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported: false,
			SupportedOps: map[string]bool{
				nvdata.CriteriaOpEqual: true,
			},
			Name:               share.ExtractModuleName(PolicyEnvSecretScannerURI),
			Module:             PolicyEnvSecretScannerURI,
			ApplicableResource: ResourceWorkload,
		},
	}
}

func (h *EnvVarSecretHandler) BuildPolicySettings(
	criteria []*nvapis.RESTAdmRuleCriterion,
) ([]byte, error) {
	if len(criteria) != 1 {
		return nil, errors.New("only one criterion is allowed")
	}

	criterion := criteria[0]
	if criterion.Value != "false" {
		return nil, fmt.Errorf("envVarSecrets supports only false value, got: %s", criterion.Value)
	}

	return []byte("{}"), nil
}
