package handlers

import (
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type ContainerRunningAsUserHandler struct {
	BasePolicyHandler
}

const (
	RuleRunAsRoot                   = "runAsRoot"
	PolicyContainerRunningAsUserURI = "registry://ghcr.io/kubewarden/policies/container-running-as-user:v1.0.4"
)

func NewContainerRunningAsUserHandler() *ContainerRunningAsUserHandler {
	return &ContainerRunningAsUserHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported:        false,
			SupportedOps:       map[string]bool{nvdata.CriteriaOpEqual: true},
			Name:               share.ExtractModuleName(PolicyContainerRunningAsUserURI),
			ApplicableResource: ResourceWorkload,
			Module:             PolicyContainerRunningAsUserURI,
		},
	}
}

func (h *ContainerRunningAsUserHandler) BuildPolicySettings(_ []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	return []byte("{}"), nil
}
