package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type AnnotationsPolicyHandler struct {
	BasePolicyHandler

	criteriaNegationMap map[string]string
}

const (
	PolicySettingAnnoDoesNotContainAllOf = "doesNotContainAllOf"
	PolicySettingAnnoDoesNotContainAnyOf = "doesNotContainAnyOf"
	PolicySettingAnnoContainsOtherThan   = "containsOtherThan"
	PolicySettingAnnoContainsAnyOf       = "containsAnyOf"
	PolicySettingCriteria                = "criteria"
	PolicySettingValues                  = "values"

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
			Name:   share.ExtractModuleName(share.PolicyAnnotationsPolicyURI),
			Module: share.PolicyAnnotationsPolicyURI,
		},
		criteriaNegationMap: map[string]string{
			nvdata.CriteriaOpContainsAll:       PolicySettingAnnoDoesNotContainAllOf,
			nvdata.CriteriaOpContainsAny:       PolicySettingAnnoDoesNotContainAnyOf,
			nvdata.CriteriaOpContainsOtherThan: PolicySettingAnnoContainsOtherThan,
			nvdata.CriteriaOpNotContainsAny:    PolicySettingAnnoContainsAnyOf,
		},
	}
}

func (h *AnnotationsPolicyHandler) getBoolValue(value string) (bool, error) {
	boolValue, err := strconv.ParseBool(value)
	if err != nil {
		return false, err
	}

	// NeuVector uses the opposite of the boolean value.
	// For example, if the value is "true", the policy will be disabled.
	// If the value is "false", the policy will be enabled.
	return !boolValue, nil
}

// BuildPolicySettings builds settings for a single criterion.
func (h *AnnotationsPolicyHandler) BuildPolicySettings(criterion *nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	return h.BuildGroupedPolicySettings([]*nvapis.RESTAdmRuleCriterion{criterion})
}

// BuildGroupedPolicySettings builds settings from multiple criteria that map to the same module
func (h *AnnotationsPolicyHandler) BuildGroupedPolicySettings(criteria []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	if len(criteria) != 1 {
		return nil, errors.New("only one criterion is allowed")
	}

	settings := map[string]any{}
	criterion := criteria[0]
	negationCriteria, ok := h.criteriaNegationMap[criterion.Op]
	if !ok {
		return nil, fmt.Errorf("unsupported criteria operator: %s", criterion.Op)
	}
	settings[PolicySettingCriteria] = negationCriteria
	settings[PolicySettingValues] = strings.Split(criterion.Value, ",")

	settingsBytes, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	return settingsBytes, nil
}
