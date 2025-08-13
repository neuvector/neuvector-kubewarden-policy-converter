package handlers

import (
	"encoding/json"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type ContainerRunningAsUserHandler struct {
	BasePolicyHandler
}

const (
	PolicySettingRunAsUser                           = "run_as_user"
	PolicySettingMustRunAsNonRoot                    = "MustRunAsNonRoot"
	PolicySettingValidateContainerImageConfiguration = "validate_container_image_configuration"

	RuleRunAsRoot = "runAsRoot"
)

func NewContainerRunningAsUserHandler() *ContainerRunningAsUserHandler {
	return &ContainerRunningAsUserHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported:  false,
			SupportedOps: map[string]bool{nvdata.CriteriaOpEqual: true},
			Name:         share.ExtractModuleName(share.PolicyContainerRunningAsUserURI),
			Module:       share.PolicyContainerRunningAsUserURI,
		},
	}
}

// BuildPolicySettings builds settings for a single criterion.
func (h *ContainerRunningAsUserHandler) BuildPolicySettings(criterion *nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	return h.BuildGroupedPolicySettings([]*nvapis.RESTAdmRuleCriterion{criterion})
}

// BuildGroupedPolicySettings builds settings from multiple criteria that map to the same module
// Because neuvector only limit the run as user, so converter just ensure the user must be non root, group can be any.
func (h *ContainerRunningAsUserHandler) BuildGroupedPolicySettings(_ []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	settingsBytes, err := json.Marshal(map[string]string{})
	if err != nil {
		return nil, err
	}
	return settingsBytes, nil
}
