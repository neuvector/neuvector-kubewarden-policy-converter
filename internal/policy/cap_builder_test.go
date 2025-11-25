package policy

import (
	"encoding/json"
	"errors"
	"testing"

	v1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/customrule"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/handlers"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
)

func TestCAPBuilder_GeneratePolicy(t *testing.T) {
	tests := []struct {
		name               string
		rule               *nvapis.RESTAdmissionRule
		config             share.ConversionConfig
		handlers           map[string]share.PolicyHandler
		expectedPolicyName string
		expectedModule     string
		expectedSettings   map[string]interface{}
		expectedMode       string
		expectedError      error
	}{
		{
			name: "successful policy generation with comment",
			rule: &nvapis.RESTAdmissionRule{
				ID:      1243,
				Comment: "Test Policy",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:  handlers.RuleShareIPC,
						Op:    nvdata.CriteriaOpEqual,
						Value: "true",
					},
				},
			},
			config: share.ConversionConfig{
				PolicyServer:    "test-server",
				Mode:            "monitor",
				BackgroundAudit: false,
			},
			handlers: map[string]share.PolicyHandler{
				handlers.RuleShareIPC: handlers.NewHostNamespaceHandler(),
			},
			expectedPolicyName: "neuvector-rule-1243-conversion",
			expectedModule:     handlers.PolicyHostNamespacesPSPURI,
			expectedSettings: map[string]interface{}{
				"allow_host_network": true,
				"allow_host_ipc":     false,
				"allow_host_pid":     true,
			},
			expectedMode: "monitor",
		},
		{
			name: "successful policy generation without comment",
			rule: &nvapis.RESTAdmissionRule{
				ID: 1243,
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:  handlers.RuleShareNetwork,
						Op:    nvdata.CriteriaOpEqual,
						Value: "true",
					},
				},
			},
			config: share.ConversionConfig{
				PolicyServer:    "test-server",
				Mode:            "monitor",
				BackgroundAudit: false,
			},
			handlers: map[string]share.PolicyHandler{
				handlers.RuleShareNetwork: handlers.NewHostNamespaceHandler(),
			},
			expectedPolicyName: "neuvector-rule-1243-conversion",
			expectedModule:     handlers.PolicyHostNamespacesPSPURI,
			expectedSettings: map[string]interface{}{
				"allow_host_network": false,
				"allow_host_ipc":     true,
				"allow_host_pid":     true,
			},
			expectedMode: "monitor",
		},
		{
			name: "error when handler for ShareIPC criterion is missing",
			rule: &nvapis.RESTAdmissionRule{
				ID:      1243,
				Comment: "Test Policy",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:  handlers.RuleShareIPC,
						Op:    nvdata.CriteriaOpEqual,
						Value: "true",
					},
				},
			},
			config: share.ConversionConfig{
				PolicyServer:    "test-server",
				Mode:            "monitor",
				BackgroundAudit: false,
			},
			handlers: map[string]share.PolicyHandler{
				handlers.RuleShareNetwork: handlers.NewHostNamespaceHandler(),
			},
			expectedPolicyName: "test-policy",
			expectedModule:     handlers.PolicyHostNamespacesPSPURI,
			expectedSettings: map[string]interface{}{
				"allow_host_network": true,
				"allow_host_ipc":     false,
				"allow_host_pid":     true,
			},
			expectedMode:  "monitor",
			expectedError: errors.New("no handler found for criterion: shareIpcWithHost"),
		},
		{
			name: "error when handler has multiple namespace selectors",
			rule: &nvapis.RESTAdmissionRule{
				ID:      1243,
				Comment: "Test Policy",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:  handlers.RuleShareIPC,
						Op:    nvdata.CriteriaOpEqual,
						Value: "true",
					},
					{
						Name:  handlers.RuleNamespace,
						Op:    nvdata.CriteriaOpContainsAny,
						Value: "test1",
					},
					{
						Name:  handlers.RuleNamespace,
						Op:    nvdata.CriteriaOpContainsAny,
						Value: "test2",
					},
				},
			},
			config: share.ConversionConfig{
				PolicyServer:    "test-server",
				Mode:            "monitor",
				BackgroundAudit: false,
			},
			handlers: map[string]share.PolicyHandler{
				handlers.RuleShareIPC:  handlers.NewHostNamespaceHandler(),
				handlers.RuleNamespace: handlers.NewNamespaceHandler(),
			},
			expectedError: errors.New("rule skipped: contains multiple namespace selectors"),
		},
		{
			name: "error when rule contains only customPath criterion",
			rule: &nvapis.RESTAdmissionRule{
				ID:      1001,
				Comment: "Custom Path Rule Test",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:      customrule.RuleCustom,
						Op:        nvdata.CriteriaOpContainsAll,
						Path:      "item.spec.containers[_].name",
						Type:      customrule.RuleCustom,
						Value:     "nginx,redis",
						ValueType: customrule.RuleCustom,
					},
				},
			},
			config: share.ConversionConfig{
				PolicyServer:    "test-server",
				Mode:            "monitor",
				BackgroundAudit: false,
			},
			handlers: map[string]share.PolicyHandler{
				handlers.RuleShareIPC: handlers.NewHostNamespaceHandler(),
			},
			expectedError: errors.New("no handler found for criterion: customPath"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := &CAPBuilder{
				handlers: tt.handlers,
			}

			policy, err := builder.GeneratePolicy(tt.rule, tt.config)
			require.Equal(t, tt.expectedError, err)

			if tt.expectedError != nil {
				require.Nil(t, policy)
				return
			}
			require.NotNil(t, policy)

			// Type assert to ClusterAdmissionPolicy
			admissionPolicy, ok := policy.(*v1.ClusterAdmissionPolicy)
			require.True(t, ok)

			// Verify metadata
			require.Equal(t, tt.expectedPolicyName, admissionPolicy.ObjectMeta.Name)
			require.Equal(t, clusterAdmissionPolicyKind, admissionPolicy.TypeMeta.Kind)
			require.Equal(t, kwAPIVersion, admissionPolicy.TypeMeta.APIVersion)

			// Verify spec
			require.Equal(t, tt.expectedModule, admissionPolicy.Spec.PolicySpec.Module)
			require.Equal(t, tt.config.PolicyServer, admissionPolicy.Spec.PolicySpec.PolicyServer)
			require.Equal(t, tt.config.BackgroundAudit, admissionPolicy.Spec.PolicySpec.BackgroundAudit)
			require.Equal(t, v1.PolicyMode(tt.expectedMode), admissionPolicy.Spec.PolicySpec.Mode)

			// Verify settings
			var actualSettings map[string]interface{}
			err = json.Unmarshal(admissionPolicy.Spec.PolicySpec.Settings.Raw, &actualSettings)
			require.NoError(t, err)
			require.Equal(t, tt.expectedSettings, actualSettings)

			// Verify rules
			rules := admissionPolicy.Spec.PolicySpec.Rules
			require.Len(t, rules, 3) // Default rules from BuildRules()
		})
	}
}
