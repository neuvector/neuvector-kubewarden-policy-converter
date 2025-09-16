package convert

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/handlers"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func initMockHandlers() map[string]share.PolicyHandler {
	return map[string]share.PolicyHandler{
		handlers.RuleShareIPC:     handlers.NewHostNamespaceHandler(),
		handlers.RuleShareNetwork: handlers.NewHostNamespaceHandler(),
		handlers.RuleSharePID:     handlers.NewHostNamespaceHandler(),
	}
}

// TestProcessSingleRuleFailed cover the failed cases.
func TestProcessSingleRuleFailed(t *testing.T) {
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
					{Name: handlers.RuleShareIPC, Op: "containsAny_invalid", Value: "bad1,bad2"},
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
			require.Nil(t, result.policy)
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
					{Name: handlers.RuleShareIPC, Op: "containsAny_invalid", Value: "bad1,bad2"},
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

// TestOutputPolicies_Stdout reads the test policy and rule, and converts the rule to stdout.
// Ensure the output is the same as the test policy, and no file is created.
func TestOutputPolicies_Stdout(t *testing.T) {
	testPolicy := "../../test/rules/single_criterion/share_host_ipc/not_allow_share_host_ipc/policy.yaml"
	testRule := "../../test/rules/single_criterion/share_host_ipc/not_allow_share_host_ipc/rule.json"

	testPolicyBytes, err := os.ReadFile(testPolicy)
	require.NoError(t, err)

	oldStdout := os.Stdout

	r, w, err := os.Pipe()
	require.NoError(t, err)
	//nolint:reassign // reassign is needed to capture the output for testing purposes
	os.Stdout = w

	policyServer := "default"
	converter := NewRuleConverter(share.ConversionConfig{
		PolicyServer:    policyServer,
		OutputFile:      "-",
		Mode:            "protect",
		BackgroundAudit: true,
		ShowSummary:     false,
	})
	err = converter.Convert(testRule)
	require.NoError(t, err)

	w.Close()
	//nolint:reassign // reassign is needed to capture the output for testing purposes
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)

	assert.Equal(t, buf.String(), string(testPolicyBytes))

	// Ensure no file is created, including the default output file name, and - for stdout.
	assert.NoFileExists(t, "policies.yaml")
	assert.NoFileExists(t, "-")
}

/*
Single-criterion conversion tests.
*/
func TestConvertSingleCriterion_HostNamespacePolicy(t *testing.T) {
	for _, ruleDir := range []string{
		"../../test/rules/single_criterion/share_host_ipc/not_allow_share_host_ipc",
		"../../test/rules/single_criterion/share_host_network/not_allow_share_host_network",
		"../../test/rules/single_criterion/share_host_pid/not_allow_share_host_pid",
	} {
		testRuleConversion(t, ruleDir)
	}
}

func TestConvertSingleCriterion_RunAsPrivileged(t *testing.T) {
	ruleDir := "../../test/rules/single_criterion/run_as_privilege/not_allow_run_as_privilege"
	testRuleConversion(t, ruleDir)
}

func TestConvertSingleCriterion_AllowPrivilegeEscalation(t *testing.T) {
	ruleDir := "../../test/rules/single_criterion/pod_privilege_escalation/not_allow_pod_privilege_escalation"
	testRuleConversion(t, ruleDir)
}

func TestConvertSingleCriterion_RunAsRoot(t *testing.T) {
	ruleDir := "../../test/rules/single_criterion/run_as_root/not_allow_run_as_root"
	testRuleConversion(t, ruleDir)
}

func TestConvertSingleCriterion_PVCStorageClass(t *testing.T) {
	for _, ruleDir := range []string{
		"../../test/rules/single_criterion/pvc_storage_class/contains_any",
		"../../test/rules/single_criterion/pvc_storage_class/not_contains_any",
	} {
		testRuleConversion(t, ruleDir)
	}
}

func TestConvertSingleCriterion_EnvVar(t *testing.T) {
	for _, ruleDir := range []string{
		"../../test/rules/single_criterion/env_var/contains_all",
		"../../test/rules/single_criterion/env_var/contains_any",
		"../../test/rules/single_criterion/env_var/contains_other_than",
		"../../test/rules/single_criterion/env_var/not_contains_any",
	} {
		testRuleConversion(t, ruleDir)
	}
}

func TestConvertSingleCriterion_EnvVarSecret(t *testing.T) {
	ruleDir := "../../test/rules/single_criterion/env_var_secret/secret_forbid"
	testRuleConversion(t, ruleDir)
}

/*
Multi-criteria conversion tests for compound rules and edge cases.
*/
func TestConvertMultiCriteria_ShareHostIPCAndNetwork(t *testing.T) {
	ruleDir := "../../test/rules/multi_criteria/share_host_ipc_network"
	testRuleConversion(t, ruleDir)
}

func TestConvertMultiCriteria_ShareHostIPCAndPID(t *testing.T) {
	ruleDir := "../../test/rules/multi_criteria/share_host_ipc_pid"
	testRuleConversion(t, ruleDir)
}

func TestConvertMultiCriteria_ShareHostIPCPIDAndNetwork(t *testing.T) {
	ruleDir := "../../test/rules/multi_criteria/share_host_ipc_pid_network"
	testRuleConversion(t, ruleDir)
}

func TestConvertMultiCriteria_ShareHostPIDAndNetwork(t *testing.T) {
	ruleDir := "../../test/rules/multi_criteria/share_host_pid_network"
	testRuleConversion(t, ruleDir)
}

func TestConvertMultiCriteria_ShareHostIPCAndNetworkAndPVCStorageClass(t *testing.T) {
	ruleDir := "../../test/rules/multi_criteria/share_host_ipc_network_pvc_storage_class"
	testRuleConversion(t, ruleDir)
}
