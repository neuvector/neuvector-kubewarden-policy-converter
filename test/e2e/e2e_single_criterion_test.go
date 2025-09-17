package e2e

import (
	"testing"
)

const (
	ModeProtect      = "protect"
	SingleRule       = "single_criterion"
	ShareIPC         = "share_host_ipc"
	NotAllowShareIPC = "not_allow_share_host_ipc"
)

func TestConvertSingleCriterion_ShareHostIPC(t *testing.T) {
	ruleDir := "../rules/single_criterion/share_host_ipc/not_allow_share_host_ipc"
	testRuleConversion(t, ruleDir)
}

func TestConvertSingleCriterion_ShareHostPID(t *testing.T) {
	ruleDir := "../rules/single_criterion/share_host_pid/not_allow_share_host_pid"
	testRuleConversion(t, ruleDir)
}

func TestConvertSingleCriterion_ShareHostNetwork(t *testing.T) {
	ruleDir := "../rules/single_criterion/share_host_network/not_allow_share_host_network"
	testRuleConversion(t, ruleDir)
}

func TestConvertSingleCriterion_RunAsPrivileged(t *testing.T) {
	ruleDir := "../rules/single_criterion/run_as_privilege/not_allow_run_as_privilege"
	testRuleConversion(t, ruleDir)
}

func TestConvertSingleCriterion_AllowPrivilegeEscalation(t *testing.T) {
	ruleDir := "../rules/single_criterion/pod_privilege_escalation/not_allow_pod_privilege_escalation"
	testRuleConversion(t, ruleDir)
}

func TestConvertSingleCriterion_RunAsRoot(t *testing.T) {
	ruleDir := "../rules/single_criterion/run_as_root/not_allow_run_as_root"
	testRuleConversion(t, ruleDir)
}

func TestConvertSingleCriterion_ImageRule(t *testing.T) {
	for _, ruleDir := range []string{
		"../rules/single_criterion/image/contains_any",
		"../rules/single_criterion/image/not_contains_any",
	} {
		testRuleConversion(t, ruleDir)
	}
}

func TestConvertSingleCriterion_ImageRegistryRule(t *testing.T) {
	for _, ruleDir := range []string{
		"../rules/single_criterion/image_registry/contains_any",
		"../rules/single_criterion/image_registry/not_contains_any",
	} {
		testRuleConversion(t, ruleDir)
	}
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
	ruleDir := "../rules/single_criterion/env_var_secret/secret_forbid"
	testRuleConversion(t, ruleDir)
}
