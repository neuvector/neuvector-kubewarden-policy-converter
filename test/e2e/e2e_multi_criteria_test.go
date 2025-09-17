package e2e

import (
	"testing"
)

func TestConvertMultiCriteria_ShareHostIPCAndNetwork(t *testing.T) {
	ruleDir := "../rules/multi_criteria/share_host_ipc_network"
	testRuleConversion(t, ruleDir)
}

func TestConvertMultiCriteria_ShareHostIPCAndPID(t *testing.T) {
	ruleDir := "../rules/multi_criteria/share_host_ipc_pid"
	testRuleConversion(t, ruleDir)
}

func TestConvertMultiCriteria_ShareHostIPCPIDAndNetwork(t *testing.T) {
	ruleDir := "../rules/multi_criteria/share_host_ipc_pid_network"
	testRuleConversion(t, ruleDir)
}

func TestConvertMultiCriteria_ShareHostPIDAndNetwork(t *testing.T) {
	ruleDir := "../rules/multi_criteria/share_host_pid_network"
	testRuleConversion(t, ruleDir)
}

func TestConvertMultiCriteria_ImageAndImageRegistryNamespaceContainAny(t *testing.T) {
	ruleDir := "../rules/namespace_selector/image_and_image_registry_namespace_contain_any"
	testRuleConversion(t, ruleDir)
}
