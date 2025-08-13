package handlers

import (
	"encoding/json"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type AllowPrivilegedEscalationHandler struct {
	BasePolicyHandler
}

const (
	PolicySettingAllowPrivilegedEscalation = "default_allow_privilege_escalation"

	RuleAllowPrivilegedEscalation = "allowPrivEscalation"
)

func NewAllowPrivilegedEscalationHandler() *AllowPrivilegedEscalationHandler {
	return &AllowPrivilegedEscalationHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported:  false,
			SupportedOps: map[string]bool{nvdata.CriteriaOpEqual: true},
			Name:         share.ExtractModuleName(share.PolicyAllowPrivEscalationURI),
			Module:       share.PolicyAllowPrivEscalationURI,
		},
	}
}

// BuildPolicySettings builds settings for a single criterion.
func (h *AllowPrivilegedEscalationHandler) BuildPolicySettings(criterion *nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	return h.BuildGroupedPolicySettings([]*nvapis.RESTAdmRuleCriterion{criterion})
}

// BuildGroupedPolicySettings builds settings from multiple criteria that map to the same module
// Because the the privileged escation in neuvector only return true, so we fix the map to be true for now.
func (h *AllowPrivilegedEscalationHandler) BuildGroupedPolicySettings(
	_ []*nvapis.RESTAdmRuleCriterion,
) ([]byte, error) {
	settings := map[string]bool{
		PolicySettingAllowPrivilegedEscalation: true,
	}

	settingsBytes, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	return settingsBytes, nil
}
