package handlers

import (
	"encoding/json"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type PodPrivilegedHandler struct {
	BasePolicyHandler
}

const (
	RuleRunAsPrivileged = "runAsPrivileged"
)

func NewPodPrivilegedHandler() *PodPrivilegedHandler {
	return &PodPrivilegedHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported:  false,
			SupportedOps: map[string]bool{nvdata.CriteriaOpEqual: true},
			Name:         share.ExtractModuleName(share.PolicyPodPrivilegedURI),
			Module:       share.PolicyPodPrivilegedURI,
		},
	}
}

// BuildPolicySettings builds settings for a single criterion.
func (h *PodPrivilegedHandler) BuildPolicySettings(criterion *nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	return h.BuildGroupedPolicySettings([]*nvapis.RESTAdmRuleCriterion{criterion})
}

// BuildGroupedPolicySettings builds settings from multiple criteria that map to the same module
// Because only support the disable run as privileged, so converter just use the module and use the default setting.
func (h *PodPrivilegedHandler) BuildGroupedPolicySettings(_ []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	settingsBytes, err := json.Marshal(map[string]bool{})
	if err != nil {
		return nil, err
	}
	return settingsBytes, nil
}
