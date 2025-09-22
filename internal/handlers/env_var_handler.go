package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type EnvVarHandler struct {
	BasePolicyHandler

	// criteriaNegationMap maps criteria operations to their negated forms for deny-action neuvector rule conversion.
	// Since converter only support deny actions, positive criteria must be converted to negative counterparts.
	criteriaNegationMap map[string]string
}

const (
	PolicyEnvironmentVariableURI = "registry://ghcr.io/kubewarden/policies/environment-variable-policy:v3.0.2"

	RuleEnvVars = "envVars"
)

func NewEnvVarHandler() *EnvVarHandler {
	return &EnvVarHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported: false,
			SupportedOps: map[string]bool{
				nvdata.CriteriaOpContainsAll:       true,
				nvdata.CriteriaOpContainsAny:       true,
				nvdata.CriteriaOpContainsOtherThan: true,
				nvdata.CriteriaOpNotContainsAny:    true,
			},
			Name:               share.ExtractModuleName(PolicyEnvironmentVariableURI),
			Module:             PolicyEnvironmentVariableURI,
			ApplicableResource: ResourceWorkload,
		},
		criteriaNegationMap: map[string]string{
			nvdata.CriteriaOpContainsAll:       "doesNotContainAllOf",
			nvdata.CriteriaOpContainsAny:       "doesNotContainAnyOf",
			nvdata.CriteriaOpContainsOtherThan: "doesNotContainOtherThan",
			nvdata.CriteriaOpNotContainsAny:    "containsAnyOf",
		},
	}
}

func (h *EnvVarHandler) BuildPolicySettings(criteria []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	if len(criteria) != 1 {
		return nil, errors.New("only one criterion is allowed")
	}

	settings := map[string]any{}
	criterion := criteria[0]
	negationCriteria, ok := h.criteriaNegationMap[criterion.Op]
	if !ok {
		return nil, fmt.Errorf("unsupported criteria operator: %s", criterion.Op)
	}
	settings["criteria"] = negationCriteria
	settings["values"] = strings.Split(criterion.Value, ",")

	settingsBytes, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	return settingsBytes, nil
}
