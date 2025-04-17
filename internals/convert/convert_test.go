package convert

import (
	"testing"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	nvapis "github.com/neuvector/neuvector/controller/api"
	"sigs.k8s.io/yaml"
)

func TestProcessSingleRule_IDLessThan1000(t *testing.T) {
	rule := &nvapis.RESTAdmissionRule{
		ID:       999,
		Category: "Test",
		Comment:  "Rule with ID less than 1000",
		Criteria: []*nvapis.RESTAdmRuleCriterion{},
		Disable:  false,
		Critical: false,
		CfgType:  "user_created",
		RuleType: "deny",
		RuleMode: "protect",
	}

	config := ConversionConfig{PolicyServer: "test-server"}

	result, yamlOut := processSingleRule(rule, config)

	// The same ID should be returned.
	if result.id != "999" {
		t.Errorf("Expected ID '999', got '%s'", result.id)
	}

	// This rule should be ignored.
	if result.status != MsgStatusSkip {
		t.Errorf("Expected status '%s', got '%s'", MsgStatusSkip, result.status)
	}

	// The notes should indicate that the rule was skipped.
	if result.notes != MsgNeuVectorRuleOnly {
		t.Errorf("Expected notes '%s', got '%s'", MsgNeuVectorRuleOnly, result.notes)
	}

	// No YAML output should be generated.
	if yamlOut != "" {
		t.Errorf("Expected empty YAML output, got '%s'", yamlOut)
	}
}

func TestProcessSingleRule_NotExistCriteria(t *testing.T) {
	rule := &nvapis.RESTAdmissionRule{
		ID:       1001,
		Category: "Test",
		Comment:  "Rule with non exist criteria",
		Criteria: []*nvapis.RESTAdmRuleCriterion{
			{
				Name:  "annotations__NOT_EXIST",
				Op:    "containsAny",
				Value: "bad1,bad2",
			},
		},
		Disable:  false,
		Critical: false,
		CfgType:  "user_created",
		RuleType: "deny",
	}

	config := ConversionConfig{PolicyServer: "test-server"}

	result, yamlOut := processSingleRule(rule, config)

	// The same ID should be returned.
	if result.id != "1001" {
		t.Errorf("Expected ID '1001', got '%s'", result.id)
	}

	// This rule should be ignored.
	if result.status != MsgStatusSkip {
		t.Errorf("Expected status '%s', got '%s'", MsgStatusSkip, result.status)
	}

	// The notes should indicate that the rule was skipped.
	if result.notes != MsgUnsupportedRuleCriteria {
		t.Errorf("Expected notes '%s', got '%s'", MsgUnsupportedRuleCriteria, result.notes)
	}

	// No YAML output should be generated.
	if yamlOut != "" {
		t.Errorf("Expected empty YAML output, got '%s'", yamlOut)
	}
}

func TestProcessSingleRule_InvalidCriteriaOperator(t *testing.T) {
	rule := &nvapis.RESTAdmissionRule{
		ID:       1001,
		Category: "Test",
		Comment:  "Rule with invalid criteria operator",
		Criteria: []*nvapis.RESTAdmRuleCriterion{
			{
				Name:  "annotations",
				Op:    "containsAny_invalid",
				Value: "bad1,bad2",
			},
		},
		Disable:  false,
		Critical: false,
		CfgType:  "user_created",
		RuleType: "deny",
	}

	config := ConversionConfig{PolicyServer: "test-server"}

	result, yamlOut := processSingleRule(rule, config)

	// The same ID should be returned.
	if result.id != "1001" {
		t.Errorf("Expected ID '1001', got '%s'", result.id)
	}

	// This rule should be ignored.
	if result.status != MsgStatusSkip {
		t.Errorf("Expected status '%s', got '%s'", MsgStatusSkip, result.status)
	}

	// The notes should indicate that the rule was skipped.
	if result.notes != MsgUnsupportedRuleCriteria {
		t.Errorf("Expected notes '%s', got '%s'", MsgUnsupportedRuleCriteria, result.notes)
	}

	// No YAML output should be generated.
	if yamlOut != "" {
		t.Errorf("Expected empty YAML output, got '%s'", yamlOut)
	}
}

func TestProcessSingleRule_ShouldUnmarshalResultYaml(t *testing.T) {
	rule := &nvapis.RESTAdmissionRule{
		ID:       1001,
		Category: "Test",
		Comment:  "Should successfully convert a valid NeuVector rule into a Kubewarden policy result",
		Criteria: []*nvapis.RESTAdmRuleCriterion{
			{
				Name:  "annotations",
				Op:    "containsAny",
				Value: "bad1,bad2",
			},
		},
		Disable:  false,
		Critical: false,
		CfgType:  "user_created",
		RuleType: "deny",
	}

	config := ConversionConfig{PolicyServer: "test-server"}

	result, yamlOut := processSingleRule(rule, config)

	// The same ID should be returned.
	if result.id != "1001" {
		t.Errorf("Expected ID '1001', got '%s'", result.id)
	}

	// This rule should be successfully converted.
	if result.status != MsgStatusOk {
		t.Errorf("Expected status '%s', got '%s'", MsgStatusOk, result.status)
	}

	// Convert the rule to YAML format.
	var policy policiesv1.ClusterAdmissionPolicy
	if err := yaml.Unmarshal([]byte(yamlOut), &policy); err != nil {
		t.Errorf("Expected a valid YAML output, got '%s'", yamlOut)
	}

	// For a single criterion, the kind should be ClusterAdmissionPolicy.
	if policy.TypeMeta.Kind != "ClusterAdmissionPolicy" {
		t.Errorf("Expected TypeMeta.Kind 'ClusterAdmissionPolicy', got '%s'", policy.TypeMeta.Kind)
	}

	if policy.ObjectMeta.Name != "neuvector-rule-1001-conversion" {
		t.Errorf("Expected ObjectMeta.Name 'neuvector-rule-1001-conversion', got '%s'", policy.TypeMeta.Kind)
	}

	if policy.Spec.PolicySpec.PolicyServer != config.PolicyServer {
		t.Errorf("Expected PolicyServer '%s', got '%s'", config.PolicyServer, policy.Spec.PolicySpec.PolicyServer)
	}

	// annotation criterion should uses CEL policy module
	if policy.Spec.PolicySpec.Module != policyCEL {
		t.Errorf("Expected Module '%s', got '%s'", policyCEL, policy.Spec.PolicySpec.Module)
	}
}

func TestProcessSingleRule_NamespaceCriterionShouldUseMatchCondition(t *testing.T) {
	rule := &nvapis.RESTAdmissionRule{
		ID:       1001,
		Category: "Test",
		Comment:  "Should successfully convert a namespace criterion to use MatchConditions",
		Criteria: []*nvapis.RESTAdmRuleCriterion{
			{
				Name:  "annotations",
				Op:    "containsAny",
				Value: "bad1,bad2",
			},
			{
				Name:  "namespace",
				Op:    "containsAny",
				Value: "test",
			},
		},
		Disable:  false,
		Critical: false,
		CfgType:  "user_created",
		RuleType: "deny",
	}

	config := ConversionConfig{PolicyServer: "test-server"}

	result, yamlOut := processSingleRule(rule, config)

	// The same ID should be returned.
	if result.id != "1001" {
		t.Errorf("Expected ID '1001', got '%s'", result.id)
	}

	// This rule should be successfully converted.
	if result.status != MsgStatusOk {
		t.Errorf("Expected status '%s', got '%s'", MsgStatusOk, result.status)
	}

	// Convert the rule to YAML format.
	var policy policiesv1.ClusterAdmissionPolicy
	if err := yaml.Unmarshal([]byte(yamlOut), &policy); err != nil {
		t.Errorf("Expected a valid YAML output, got '%s'", yamlOut)
	}

	// There should be exactly one match condition.
	if len(policy.Spec.PolicySpec.MatchConditions) != 1 {
		t.Errorf("Expected 1 MatchCondition, got '%d'", len(policy.Spec.PolicySpec.MatchConditions))
	}
}

func TestProcessSingleRule_ShouldUseGroupPolicy(t *testing.T) {
	rule := &nvapis.RESTAdmissionRule{
		ID:       1001,
		Category: "Test",
		Comment:  "Should successfully convert a valid NeuVector rule into a Kubewarden policy in ClusterAdmissionPolicyGroup",
		Criteria: []*nvapis.RESTAdmRuleCriterion{
			{
				Name:  "annotations",
				Op:    "containsAny",
				Value: "bad1,bad2",
			},
			{
				Name:  "labels",
				Op:    "containsAny",
				Value: "bad1=value1*,bad2=value2",
			},
		},
		Disable:  false,
		Critical: false,
		CfgType:  "user_created",
		RuleType: "deny",
	}

	config := ConversionConfig{PolicyServer: "test-server"}

	result, yamlOut := processSingleRule(rule, config)

	// The same ID should be returned.
	if result.id != "1001" {
		t.Errorf("Expected ID '1001', got '%s'", result.id)
	}

	// This rule should be successfully converted.
	if result.status != MsgStatusOk {
		t.Errorf("Expected status '%s', got '%s'", MsgStatusOk, result.status)
	}

	// Convert the rule to YAML format.
	var policy policiesv1.ClusterAdmissionPolicyGroup
	if err := yaml.Unmarshal([]byte(yamlOut), &policy); err != nil {
		t.Errorf("Expected a valid YAML output, got '%s'", yamlOut)
	}

	// For a single criterion, the kind should be ClusterAdmissionPolicy.
	if policy.TypeMeta.Kind != "ClusterAdmissionPolicyGroup" {
		t.Errorf("Expected TypeMeta.Kind 'ClusterAdmissionPolicyGroup', got '%s'", policy.TypeMeta.Kind)
	}

	if policy.ObjectMeta.Name != "neuvector-rule-1001-conversion" {
		t.Errorf("Expected ObjectMeta.Name 'neuvector-rule-1001-conversion', got '%s'", policy.TypeMeta.Kind)
	}

	// The number of policies must match the number of criteria (1:1 mapping).
	if len(policy.Spec.Policies) != len(rule.Criteria) {
		t.Errorf("Expected %d policies, got '%d'", len(rule.Criteria), len(policy.Spec.Policies))
	}
}
