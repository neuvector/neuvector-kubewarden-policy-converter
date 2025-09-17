package handlers

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type AnnotationsPolicyHandler struct {
	BasePolicyHandler

	// criteriaNegationMap maps criteria operations to their negated forms for deny-action neuvector rule conversion.
	// Since converter only support deny actions, positive criteria must be converted to negative counterparts.
	criteriaNegationMap map[string]string
}

const (
	PolicyAnnotationsPolicyURI = "registry://ghcr.io/kubewarden/policies/annotations:v0.1.2"

	RuleAnnotations = "annotations"
)

func NewAnnotationsPolicyHandler() *AnnotationsPolicyHandler {
	return &AnnotationsPolicyHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported: false,
			SupportedOps: map[string]bool{
				nvdata.CriteriaOpContainsAll:       true,
				nvdata.CriteriaOpContainsAny:       true,
				nvdata.CriteriaOpContainsOtherThan: true,
				nvdata.CriteriaOpNotContainsAny:    true,
			},
			Name:               share.ExtractModuleName(PolicyAnnotationsPolicyURI),
			Module:             PolicyAnnotationsPolicyURI,
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

func (h *AnnotationsPolicyHandler) BuildPolicySettings(criteria []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	if len(criteria) != 1 {
		return nil, errors.New("only one criterion is allowed")
	}

	settings := map[string]any{}
	criterion := criteria[0]
	settings["criteria"] = h.criteriaNegationMap[criterion.Op]
	settings["values"] = strings.Split(criterion.Value, ",")

	settingsBytes, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	return settingsBytes, nil
}
