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
	AllowHostIPC     = "allow_host_ipc"
	AllowHostNetwork = "allow_host_network"
	AllowHostPID     = "allow_host_pid"

	ShareIPC     = "shareIpcWithHost"
	ShareNetwork = "shareNetWithHost"
	SharePID     = "sharePidWithHost"
)

func NewHostNamespaceHandler() *HostNamespaceHandler {
	return &HostNamespaceHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported:  false,
			SupportedOps: map[string]bool{nvdata.CriteriaOpEqual: true},
			Name:         share.ExtractModuleName(share.PolicyHostNamespacesPSPURI),
			Module:       share.PolicyHostNamespacesPSPURI,
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

func (h *HostNamespaceHandler) GetModule() string {
	return share.PolicyHostNamespacesPSPURI
}

// BuildPolicySettings builds settings for a single criterion.
func (h *HostNamespaceHandler) BuildPolicySettings(criterion *nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	return h.BuildGroupedPolicySettings([]*nvapis.RESTAdmRuleCriterion{criterion})
}

// BuildGroupedPolicySettings builds settings from multiple criteria that map to the same module
// This allows combining shareIPC, shareNetwork, and sharePID rules into a single policy.
func (h *HostNamespaceHandler) BuildGroupedPolicySettings(criteria []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	settings := map[string]bool{
		AllowHostIPC:     true,
		AllowHostPID:     true,
		AllowHostNetwork: true,
	}

	// Process each criterion and set the appropriate flag
	var err error
	for _, criterion := range criteria {
		switch criterion.Name {
		case ShareIPC:
			settings[AllowHostIPC], err = h.getBoolValue(criterion.Value)
			if err != nil {
				return nil, err
			}
		case ShareNetwork:
			settings[AllowHostNetwork], err = h.getBoolValue(criterion.Value)
			if err != nil {
				return nil, err
			}
		case SharePID:
			settings[AllowHostPID], err = h.getBoolValue(criterion.Value)
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
