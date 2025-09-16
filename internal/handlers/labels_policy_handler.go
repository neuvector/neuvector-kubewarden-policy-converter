//nolint:dupl // annotations and labels handlers have similar structure by design
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

type LabelsPolicyHandler struct {
	BasePolicyHandler

	criteriaNegationMap map[string]string
}

const (
	PolicyLabelsPolicyURI = "registry://ghcr.io/kubewarden/policies/labels:v0.1.0"

	RuleLabels = "labels"
)

func NewLabelsPolicyHandler() *LabelsPolicyHandler {
	return &LabelsPolicyHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported: false,
			SupportedOps: map[string]bool{
				nvdata.CriteriaOpContainsAll:       true,
				nvdata.CriteriaOpContainsAny:       true,
				nvdata.CriteriaOpContainsOtherThan: true,
				nvdata.CriteriaOpNotContainsAny:    true,
			},
			Name:               share.ExtractModuleName(PolicyLabelsPolicyURI),
			Module:             PolicyLabelsPolicyURI,
			ApplicableResource: ResourceWorkload,
		},
		criteriaNegationMap: map[string]string{
			nvdata.CriteriaOpContainsAll:       "doesNotContainAllOf",
			nvdata.CriteriaOpContainsAny:       "doesNotContainAnyOf",
			nvdata.CriteriaOpContainsOtherThan: "containsOtherThan",
			nvdata.CriteriaOpNotContainsAny:    "containsAnyOf",
		},
	}
}

func (h *LabelsPolicyHandler) BuildPolicySettings(criteria []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
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
