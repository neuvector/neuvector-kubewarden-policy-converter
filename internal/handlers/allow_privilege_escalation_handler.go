package handlers

import (
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type AllowPrivilegedEscalationHandler struct {
	BasePolicyHandler
}

const (
	RuleAllowPrivilegedEscalation = "allowPrivEscalation"

	PolicyAllowPrivEscalationURI = "registry://ghcr.io/kubewarden/policies/allow-privilege-escalation-psp:v1.0.0"
)

func NewAllowPrivilegedEscalationHandler() *AllowPrivilegedEscalationHandler {
	return &AllowPrivilegedEscalationHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported:  false,
			SupportedOps: map[string]bool{nvdata.CriteriaOpEqual: true},
			Name:         share.ExtractModuleName(PolicyAllowPrivEscalationURI),
			Module:       PolicyAllowPrivEscalationURI,
		},
	}
}

func (h *AllowPrivilegedEscalationHandler) BuildPolicySettings(
	_ []*nvapis.RESTAdmRuleCriterion,
) ([]byte, error) {
	// In NeuVector, the allow privilege escalation setting is always true, so we set the map value to true.
	return []byte(`{"default_allow_privilege_escalation":true}`), nil
}
