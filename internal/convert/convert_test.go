package convert

import (
	"errors"
	"fmt"
	"testing"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/handlers"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	"github.com/stretchr/testify/require"
)

func initMockHandlers() map[string]share.PolicyHandler {
	return map[string]share.PolicyHandler{
		handlers.ShareIPC:     handlers.NewHostNamespaceHandler(),
		handlers.ShareNetwork: handlers.NewHostNamespaceHandler(),
		handlers.SharePID:     handlers.NewHostNamespaceHandler(),
	}
}

func TestProcessSingleRule(t *testing.T) {
	var (
		caPolicy      *policiesv1.ClusterAdmissionPolicy
		caPolicyGroup *policiesv1.ClusterAdmissionPolicyGroup
		ok            bool
	)

	tests := []struct {
		name               string
		rule               *nvapis.RESTAdmissionRule
		expectedID         uint32
		expectedPass       bool
		expectedNotes      string
		expectedPolicyType interface{}
		validatePolicy     func(t *testing.T, policy interface{}, policyServer string)
	}{
		{
			name: "ID less than 1000 should be skipped",
			rule: &nvapis.RESTAdmissionRule{
				ID:       999,
				Category: "Test",
				Comment:  "Rule with ID less than 1000",
				Criteria: []*nvapis.RESTAdmRuleCriterion{},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: "deny",
				RuleMode: "protect",
			},
			expectedID:    999,
			expectedPass:  false,
			expectedNotes: share.MsgNeuVectorRuleOnly,
		},
		{
			name: "Non-existing criteria should be skipped",
			rule: &nvapis.RESTAdmissionRule{
				ID:       1001,
				Category: "Test",
				Comment:  "Rule with non exist criteria",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: "annotations__NOT_EXIST", Op: "containsAny", Value: "bad1,bad2"},
				},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: "deny",
			},
			expectedID:    1001,
			expectedPass:  false,
			expectedNotes: fmt.Sprintf("%s: %s", share.MsgUnsupportedRuleCriteria, "annotations__NOT_EXIST"),
		},
		{
			name: "Invalid criteria operator should be skipped",
			rule: &nvapis.RESTAdmissionRule{
				ID:       1001,
				Category: "Test",
				Comment:  "Rule with invalid criteria operator",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: "shareIpcWithHost", Op: "containsAny_invalid", Value: "bad1,bad2"},
				},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: "deny",
			},
			expectedID:    1001,
			expectedPass:  false,
			expectedNotes: fmt.Sprintf("%s: %s", share.MsgUnsupportedCriteriaOperator, "containsAny_invalid"),
		},
		{
			name: "Valid rule should unmarshal to ClusterAdmissionPolicy",
			rule: &nvapis.RESTAdmissionRule{
				ID:       1001,
				Category: "Test",
				Comment:  "Valid rule",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: "shareIpcWithHost", Op: "=", Value: "true"},
				},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: "deny",
			},
			expectedID:         1001,
			expectedPass:       true,
			expectedNotes:      share.MsgRuleConvertedSuccessfully,
			expectedPolicyType: &policiesv1.ClusterAdmissionPolicy{},
			validatePolicy: func(t *testing.T, policy interface{}, policyServer string) {
				caPolicy, ok = policy.(*policiesv1.ClusterAdmissionPolicy)
				require.True(t, ok, "Expected ClusterAdmissionPolicy, got %T", policy)
				require.NotNil(t, caPolicy)
				require.Equal(t, "ClusterAdmissionPolicy", caPolicy.Kind)
				require.Equal(t, "valid-rule", caPolicy.Name)
				require.Equal(t, policyServer, caPolicy.Spec.PolicyServer)
				require.Equal(t, share.PolicyHostNamespacesPSPURI, caPolicy.Spec.PolicySpec.Module)
			},
		},
		{
			name: "Namespace criterion should use MatchConditions",
			rule: &nvapis.RESTAdmissionRule{
				ID:       1001,
				Category: "Test",
				Comment:  "Namespace criterion",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: "shareIpcWithHost", Op: "=", Value: "true"},
					{Name: "sharePidWithHost", Op: "=", Value: "true"},
				},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: "deny",
			},
			expectedID:         1001,
			expectedPass:       true,
			expectedNotes:      share.MsgRuleConvertedSuccessfully,
			expectedPolicyType: &policiesv1.ClusterAdmissionPolicyGroup{},
			validatePolicy: func(t *testing.T, policy interface{}, policyServer string) {
				caPolicyGroup, ok = policy.(*policiesv1.ClusterAdmissionPolicyGroup)
				require.True(t, ok, "Expected ClusterAdmissionPolicyGroup, got %T", policy)
				require.NotNil(t, caPolicyGroup)
				require.Equal(t, "ClusterAdmissionPolicyGroup", caPolicyGroup.Kind)
				require.Equal(t, policyServer, caPolicy.Spec.PolicyServer)
				require.Equal(t, share.PolicyHostNamespacesPSPURI, caPolicy.Spec.PolicySpec.Module)
			},
		},
	}

	policyServer := "test-server"
	converter := NewRuleConverter(share.ConversionConfig{
		PolicyServer: policyServer,
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := converter.convertRule(tt.rule)
			require.Equal(t, tt.expectedID, result.id)
			require.Equal(t, tt.expectedPass, result.pass)
			require.Equal(t, tt.expectedNotes, result.notes)

			// Check policy type based on status
			if result.pass {
				require.NotNil(t, result.policy)
				require.IsType(t, tt.expectedPolicyType, result.policy)
				if tt.validatePolicy != nil {
					tt.validatePolicy(t, result.policy, policyServer)
				}
			} else {
				require.Nil(t, result.policy)
			}
		})
	}
}

func TestValidateAndFilterRule(t *testing.T) {
	tests := []struct {
		name          string
		rule          *nvapis.RESTAdmissionRule
		expectedError error
	}{
		{
			name: "Rule with ID less than 1000 should return NeuVector rule only error",
			rule: &nvapis.RESTAdmissionRule{
				ID:       999,
				Category: "Test",
				Comment:  "Rule with ID less than 1000",
				Criteria: []*nvapis.RESTAdmRuleCriterion{},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: "deny",
				RuleMode: "protect",
			},
			expectedError: errors.New(share.MsgNeuVectorRuleOnly),
		},
		{
			name: "Rule with unsupported type should return only deny rule supported error",
			rule: &nvapis.RESTAdmissionRule{
				ID:       1999,
				Category: "Test",
				Comment:  "Rule with unsupported type",
				Criteria: []*nvapis.RESTAdmRuleCriterion{},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: "denyr",
				RuleMode: "protect",
			},
			expectedError: fmt.Errorf("%s got %s", share.MsgOnlyDenyRuleSupported, "denyr"),
		},
		{
			name: "Rule with ValidatingExceptRuleType should return only deny rule supported error",
			rule: &nvapis.RESTAdmissionRule{
				ID:       1999,
				Category: "Test",
				Comment:  "Rule with ValidatingExceptRuleType",
				Criteria: []*nvapis.RESTAdmRuleCriterion{},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: nvapis.ValidatingExceptRuleType,
				RuleMode: "protect",
			},
			expectedError: fmt.Errorf("%s got %s", share.MsgOnlyDenyRuleSupported, nvapis.ValidatingExceptRuleType),
		},
		{
			name: "Rule with ValidatingAllowRuleType should return only deny rule supported error",
			rule: &nvapis.RESTAdmissionRule{
				ID:       1999,
				Category: "Test",
				Comment:  "Rule with ValidatingAllowRuleType",
				Criteria: []*nvapis.RESTAdmRuleCriterion{},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: nvapis.ValidatingAllowRuleType,
				RuleMode: "protect",
			},
			expectedError: fmt.Errorf("%s got %s", share.MsgOnlyDenyRuleSupported, nvapis.ValidatingAllowRuleType),
		},
		{
			name: "Disabled rule should return rule disabled error",
			rule: &nvapis.RESTAdmissionRule{
				ID:       2999,
				Category: "Test",
				Comment:  "Disabled rule",
				Criteria: []*nvapis.RESTAdmRuleCriterion{},
				Disable:  true,
				Critical: false,
				CfgType:  "user_created",
				RuleType: "deny",
				RuleMode: "protect",
			},
			expectedError: fmt.Errorf("%s, got %t", share.MsgRuleDisabled, true),
		},
		{
			name: "Rule with non-existing criteria should return unsupported rule criteria error",
			rule: &nvapis.RESTAdmissionRule{
				ID:       1001,
				Category: "Test",
				Comment:  "Rule with non-existing criteria",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: "annotations__NOT_EXIST", Op: "containsAny", Value: "bad1,bad2"},
				},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: "deny",
			},
			expectedError: fmt.Errorf("%s: %s", share.MsgUnsupportedRuleCriteria, "annotations__NOT_EXIST"),
		},
		{
			name: "Rule with invalid criteria operator should return unsupported criteria operator error",
			rule: &nvapis.RESTAdmissionRule{
				ID:       1001,
				Category: "Test",
				Comment:  "Rule with invalid criteria operator",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: "shareIpcWithHost", Op: "containsAny_invalid", Value: "bad1,bad2"},
				},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: "deny",
			},
			expectedError: fmt.Errorf("%s: %s", share.MsgUnsupportedCriteriaOperator, "containsAny_invalid"),
		},
	}

	policyServer := "test-server"
	converter := NewRuleConverter(share.ConversionConfig{
		PolicyServer: policyServer,
	})

	converter.handlers = initMockHandlers()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := converter.validateRule(tt.rule)
			require.Equal(t, tt.expectedError, err)
		})
	}
}
