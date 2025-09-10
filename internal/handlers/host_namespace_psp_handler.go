package handlers

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type HostNamespaceHandler struct {
	BasePolicyHandler
}

const (
	PolicySettingAllowHostIPC     = "allow_host_ipc"
	PolicySettingAllowHostNetwork = "allow_host_network"
	PolicySettingAllowHostPID     = "allow_host_pid"

	RuleShareIPC     = "shareIpcWithHost"
	RuleShareNetwork = "shareNetWithHost"
	RuleSharePID     = "sharePidWithHost"

	PolicyHostNamespacesPSPURI = "registry://ghcr.io/kubewarden/policies/host-namespaces-psp:v1.1.0"
)

func NewHostNamespaceHandler() *HostNamespaceHandler {
	return &HostNamespaceHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported:        false,
			SupportedOps:       map[string]bool{nvdata.CriteriaOpEqual: true},
			Name:               share.ExtractModuleName(PolicyHostNamespacesPSPURI),
			ApplicableResource: ResourceWorkload,
			Module:             PolicyHostNamespacesPSPURI,
		},
	}
}

func (h *HostNamespaceHandler) getBoolValue(value string) (bool, error) {
	boolValue, err := strconv.ParseBool(value)
	if err != nil {
		return false, err
	}

	// NeuVector uses the opposite of the boolean value.
	// For example, if the value is "true", the policy will be disabled.
	// If the value is "false", the policy will be enabled.
	return !boolValue, nil
}

// BuildPolicySettings allows combining shareIPC, shareNetwork, and sharePID rules into a single policy.
func (h *HostNamespaceHandler) BuildPolicySettings(criteria []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	settings := map[string]bool{
		PolicySettingAllowHostIPC:     true,
		PolicySettingAllowHostPID:     true,
		PolicySettingAllowHostNetwork: true,
	}

	// Process each criterion and set the appropriate flag
	var err error
	for _, criterion := range criteria {
		switch criterion.Name {
		case RuleShareIPC:
			settings[PolicySettingAllowHostIPC], err = h.getBoolValue(criterion.Value)
			if err != nil {
				return nil, err
			}
		case RuleShareNetwork:
			settings[PolicySettingAllowHostNetwork], err = h.getBoolValue(criterion.Value)
			if err != nil {
				return nil, err
			}
		case RuleSharePID:
			settings[PolicySettingAllowHostPID], err = h.getBoolValue(criterion.Value)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported criterion: %s", criterion.Name)
		}
	}

	settingsBytes, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	return settingsBytes, nil
}
