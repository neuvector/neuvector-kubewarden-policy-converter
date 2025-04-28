package convert

import (
	"testing"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	nvapis "github.com/neuvector/neuvector/controller/api"
)

func TestProcessSingleRule(t *testing.T) {
	tests := []struct {
		name             string
		rule             *nvapis.RESTAdmissionRule
		expectedID       uint32
		expectedStatus   string
		expectedNotes    string
		expectPolicyNil  bool
		expectPolicyCap  bool
		expectPolicyCapg bool
		validatePolicy   func(t *testing.T, policy interface{}, policyServer string)
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
			expectedID:      999,
			expectedStatus:  MsgStatusSkip,
			expectedNotes:   MsgNeuVectorRuleOnly,
			expectPolicyNil: true,
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
			expectedID:      1001,
			expectedStatus:  MsgStatusSkip,
			expectedNotes:   MsgUnsupportedRuleCriteria,
			expectPolicyNil: true,
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
			expectedID:      1001,
			expectedStatus:  MsgStatusSkip,
			expectPolicyNil: true,
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
			expectedID:      1001,
			expectedStatus:  MsgStatusOk,
			expectPolicyCap: true,
			validatePolicy: func(t *testing.T, policy interface{}, policyServer string) {
				cap, ok := policy.(*policiesv1.ClusterAdmissionPolicy)
				if !ok {
					t.Fatalf("Expected ClusterAdmissionPolicy, got %T", policy)
				}
				if cap.Kind != "ClusterAdmissionPolicy" {
					t.Errorf("Expected Kind 'ClusterAdmissionPolicy', got '%s'", cap.Kind)
				}
				if cap.Name != "neuvector-rule-1001-conversion" {
					t.Errorf("Expected Name 'neuvector-rule-1001-conversion', got '%s'", cap.Name)
				}
				if cap.Spec.PolicyServer != policyServer {
					t.Errorf("Expected PolicyServer '%s', got '%s'", policyServer, cap.Spec.PolicyServer)
				}
				if cap.Spec.PolicySpec.Module != policyCEL {
					t.Errorf("Expected Module '%s', got '%s'", policyCEL, cap.Spec.PolicySpec.Module)
				}
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
			expectedID:      1001,
			expectedStatus:  MsgStatusOk,
			expectPolicyCap: true,
			validatePolicy: func(t *testing.T, policy interface{}, policyServer string) {
				cap, ok := policy.(*policiesv1.ClusterAdmissionPolicy)
				if !ok {
					t.Fatalf("Expected ClusterAdmissionPolicy, got %T", policy)
				}
				if len(cap.Spec.PolicySpec.MatchConditions) != 1 {
					t.Errorf("Expected 1 MatchCondition, got '%d'", len(cap.Spec.PolicySpec.MatchConditions))
				}
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
			expectedID:       1001,
			expectedStatus:   MsgStatusOk,
			expectPolicyCapg: true,
			validatePolicy: func(t *testing.T, policy interface{}, policyServer string) {
				capg, ok := policy.(*policiesv1.ClusterAdmissionPolicyGroup)
				if !ok {
					t.Fatalf("Expected ClusterAdmissionPolicyGroup, got %T", policy)
				}
				if capg.Kind != "ClusterAdmissionPolicyGroup" {
					t.Errorf("Expected Kind 'ClusterAdmissionPolicyGroup', got '%s'", capg.Kind)
				}
				if capg.Name != "neuvector-rule-1001-conversion" {
					t.Errorf("Expected Name 'neuvector-rule-1001-conversion', got '%s'", capg.Name)
				}
				if len(capg.Spec.Policies) != 2 {
					t.Errorf("Expected 2 policies inside ClusterAdmissionPolicyGroup, got '%d'", len(capg.Spec.Policies))
				}
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

			if result.id != tt.expectedID {
				t.Errorf("Expected ID '%d', got '%d'", tt.expectedID, result.id)
			}

			if result.status != tt.expectedStatus {
				t.Errorf("Expected status '%s', got '%s'", tt.expectedStatus, result.status)
			}

			if tt.expectedNotes != "" && result.notes != tt.expectedNotes {
				t.Errorf("Expected notes '%s', got '%s'", tt.expectedNotes, result.notes)
			}

			if tt.expectPolicyNil && result.policy != nil {
				t.Errorf("Expected policy to be nil, got '%v'", result.policy)
			}

			if tt.expectPolicyCap || tt.expectPolicyCapg {
				if result.policy == nil {
					t.Fatal("Expected policy not nil")
				}
				if tt.validatePolicy != nil {
					tt.validatePolicy(t, result.policy, policyServer)
				}
			}
		})
	}
}
