package handlers

import (
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type PodPrivilegedHandler struct {
	BasePolicyHandler
}

const (
	RuleRunAsPrivileged    = "runAsPrivileged"
	PolicyPodPrivilegedURI = "registry://ghcr.io/kubewarden/policies/pod-privileged:v1.0.3"
)

func NewPodPrivilegedHandler() *PodPrivilegedHandler {
	return &PodPrivilegedHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported:        false,
			SupportedOps:       map[string]bool{nvdata.CriteriaOpEqual: true},
			Name:               share.ExtractModuleName(PolicyPodPrivilegedURI),
			ApplicableResource: ResourceWorkload,
			Module:             PolicyPodPrivilegedURI,
		},
	}
}

func (h *PodPrivilegedHandler) BuildPolicySettings(_ []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	// This Kubewarden policy doesn't have any settings.
	return []byte("{}"), nil
}
