package policy

import (
	"encoding/json"
	"errors"
	"testing"

	v1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/handlers"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
)

func TestCAPGBuilder_GeneratePolicy(t *testing.T) {
	tests := []struct {
		name                string
		rule                *nvapis.RESTAdmissionRule
		config              share.ConversionConfig
		handlers            map[string]share.PolicyHandler
		expectedPolicyName  string
		expectedPoliciesLen int
		expectedError       error
		expectedMode        string
		expectedMessage     string
	}{
		{
			name: "single criterion - uses BuildPolicySettings",
			rule: &nvapis.RESTAdmissionRule{
				ID:       1234,
				Comment:  "Single Criterion Test",
				RuleMode: "protect",
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
				BackgroundAudit: true,
			},
			handlers: map[string]share.PolicyHandler{
				handlers.RuleShareIPC: handlers.NewHostNamespaceHandler(),
			},
			expectedPolicyName:  "neuvector-rule-1234-conversion",
			expectedPoliciesLen: 1,
			expectedMode:        "monitor",
			expectedMessage:     "violate NeuVector rule (id=1234), comment Single Criterion Test",
			expectedError:       nil,
		},
		{
			name: "multiple criteria same module - uses BuildGroupedPolicySettings",
			rule: &nvapis.RESTAdmissionRule{
				ID:      1235,
				Comment: "Multiple Same Module",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:  handlers.RuleShareIPC,
						Op:    nvdata.CriteriaOpEqual,
						Value: "true",
					},
					{
						Name:  handlers.RuleShareNetwork,
						Op:    nvdata.CriteriaOpEqual,
						Value: "false",
					},
				},
			},
			config: share.ConversionConfig{
				PolicyServer:    "test-server",
				Mode:            "monitor",
				BackgroundAudit: false,
			},
			handlers: map[string]share.PolicyHandler{
				handlers.RuleShareIPC:     handlers.NewHostNamespaceHandler(),
				handlers.RuleShareNetwork: handlers.NewHostNamespaceHandler(),
			},
			expectedPolicyName:  "neuvector-rule-1235-conversion",
			expectedPoliciesLen: 1,
			expectedMode:        "monitor",
			expectedMessage:     "violate NeuVector rule (id=1235), comment Multiple Same Module",
		},
		{
			name: "handler not found error",
			rule: &nvapis.RESTAdmissionRule{
				ID: 101,
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:  "unknownCriterion",
						Op:    nvdata.CriteriaOpEqual,
						Value: "true",
					},
				},
			},
			config: share.ConversionConfig{
				Mode: "monitor",
			},
			handlers:      map[string]share.PolicyHandler{},
			expectedError: errors.New("no handler found for criterion: unknownCriterion"),
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
						Name:  handlers.RuleShareNetwork,
						Op:    nvdata.CriteriaOpEqual,
						Value: "false",
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
				handlers.RuleShareIPC:     handlers.NewHostNamespaceHandler(),
				handlers.RuleShareNetwork: handlers.NewHostNamespaceHandler(),
				handlers.RuleNamespace:    handlers.NewNamespaceHandler(),
			},
			expectedError: errors.New("rule skipped: contains multiple namespace selectors"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := &CAPGBuilder{
				handlers: tt.handlers,
			}

			policy, err := builder.GeneratePolicy(tt.rule, tt.config)
			require.Equal(t, tt.expectedError, err)

			if tt.expectedError != nil {
				require.Nil(t, policy)
				return
			}

			require.NotNil(t, policy)

			// Type assert to ClusterAdmissionPolicyGroup
			capg, ok := policy.(*v1.ClusterAdmissionPolicyGroup)
			require.True(t, ok)

			// Verify metadata
			require.Equal(t, tt.expectedPolicyName, capg.ObjectMeta.Name)
			require.Equal(t, clusterAdmissionPolicyGroupKind, capg.TypeMeta.Kind)
			require.Equal(t, kwAPIVersion, capg.TypeMeta.APIVersion)

			// Verify spec
			require.Equal(t, tt.config.PolicyServer, capg.Spec.GroupSpec.PolicyServer)
			require.Equal(t, tt.config.BackgroundAudit, capg.Spec.GroupSpec.BackgroundAudit)
			require.Equal(t, v1.PolicyMode(tt.expectedMode), capg.Spec.GroupSpec.Mode)
			require.Equal(t, tt.expectedMessage, capg.Spec.GroupSpec.Message)

			// Verify policies count
			require.Len(t, capg.Spec.Policies, tt.expectedPoliciesLen)

			// Verify rules
			rules := capg.Spec.GroupSpec.Rules
			require.Len(t, rules, 3) // Default rules from BuildRules()

			// Verify that each policy has proper settings
			for policyName, member := range capg.Spec.Policies {
				require.NotEmpty(t, policyName)
				require.NotEmpty(t, member.Module)
				require.NotEmpty(t, member.Settings.Raw)

				// Verify settings can be unmarshaled
				var settings map[string]interface{}
				err = json.Unmarshal(member.Settings.Raw, &settings)
				require.NoError(t, err)
				require.NotEmpty(t, settings)
			}
		})
	}
}
