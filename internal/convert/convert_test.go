package convert

import (
	"testing"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	nvapis "github.com/neuvector/neuvector/controller/api"
	"github.com/stretchr/testify/require"
)

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
			expectedNotes: MsgNeuVectorRuleOnly,
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
			expectedNotes: MsgUnsupportedRuleCriteria,
		},
		{
			name: "Invalid criteria operator should be skipped",
			rule: &nvapis.RESTAdmissionRule{
				ID:       1001,
				Category: "Test",
				Comment:  "Rule with invalid criteria operator",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: "annotations", Op: "containsAny_invalid", Value: "bad1,bad2"},
				},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: "deny",
			},
			expectedID:    1001,
			expectedPass:  false,
			expectedNotes: MsgUnsupportedCriteriaOperator,
		},
		{
			name: "Valid rule should unmarshal to ClusterAdmissionPolicy",
			rule: &nvapis.RESTAdmissionRule{
				ID:       1001,
				Category: "Test",
				Comment:  "Valid rule",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: "annotations", Op: "containsAny", Value: "bad1,bad2"},
				},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: "deny",
			},
			expectedID:         1001,
			expectedPass:       true,
			expectedNotes:      MsgRuleConvertedSuccessfully,
			expectedPolicyType: &policiesv1.ClusterAdmissionPolicy{},
			validatePolicy: func(t *testing.T, policy interface{}, policyServer string) {
				caPolicy, ok = policy.(*policiesv1.ClusterAdmissionPolicy)
				require.True(t, ok, "Expected ClusterAdmissionPolicy, got %T", policy)
				require.NotNil(t, caPolicy)
				require.Equal(t, "ClusterAdmissionPolicy", caPolicy.Kind)
				require.Equal(t, "neuvector-rule-1001-conversion", caPolicy.Name)
				require.Equal(t, policyServer, caPolicy.Spec.PolicyServer)
				require.Equal(t, policyCEL, caPolicy.Spec.PolicySpec.Module)
			},
		},
		{
			name: "Namespace criterion should use MatchConditions",
			rule: &nvapis.RESTAdmissionRule{
				ID:       1001,
				Category: "Test",
				Comment:  "Namespace criterion",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: "annotations", Op: "containsAny", Value: "bad1,bad2"},
					{Name: "namespace", Op: "containsAny", Value: "test"},
				},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: "deny",
			},
			expectedID:         1001,
			expectedPass:       true,
			expectedNotes:      MsgRuleConvertedSuccessfully,
			expectedPolicyType: &policiesv1.ClusterAdmissionPolicy{},
			validatePolicy: func(t *testing.T, policy interface{}, policyServer string) {
				caPolicy, ok = policy.(*policiesv1.ClusterAdmissionPolicy)
				require.True(t, ok, "Expected ClusterAdmissionPolicy, got %T", policy)
				require.NotNil(t, caPolicy)
				require.Equal(t, "ClusterAdmissionPolicy", caPolicy.Kind)
				require.Equal(t, policyServer, caPolicy.Spec.PolicyServer)
				require.Len(t, caPolicy.Spec.PolicySpec.MatchConditions, 1)
			},
		},
		{
			name: "Valid rule should produce ClusterAdmissionPolicyGroup",
			rule: &nvapis.RESTAdmissionRule{
				ID:       1001,
				Category: "Test",
				Comment:  "ClusterAdmissionPolicyGroup rule",
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: "annotations", Op: "containsAny", Value: "bad1,bad2"},
					{Name: "labels", Op: "containsAny", Value: "bad1=value1*,bad2=value2"},
				},
				Disable:  false,
				Critical: false,
				CfgType:  "user_created",
				RuleType: "deny",
			},
			expectedID:         1001,
			expectedPass:       true,
			expectedNotes:      MsgRuleConvertedSuccessfully,
			expectedPolicyType: &policiesv1.ClusterAdmissionPolicyGroup{},
			validatePolicy: func(t *testing.T, policy interface{}, policyServer string) {
				caPolicyGroup, ok = policy.(*policiesv1.ClusterAdmissionPolicyGroup)
				require.True(t, ok, "Expected ClusterAdmissionPolicyGroup, got %T", policy)
				require.NotNil(t, caPolicyGroup)
				require.Equal(t, "ClusterAdmissionPolicyGroup", caPolicyGroup.Kind)
				require.Equal(t, "neuvector-rule-1001-conversion", caPolicyGroup.Name)
				require.Equal(t, policyServer, caPolicyGroup.Spec.PolicyServer)
				require.Len(t, caPolicyGroup.Spec.Policies, 2)
			},
		},
	}

	policyServer := "test-server"
	converter := NewRuleConverter(ConversionConfig{
		PolicyServer: policyServer,
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := converter.processSingleRule(tt.rule)
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
