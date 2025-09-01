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

func TestConvertShareHostIPCRule(t *testing.T) {
	ruleDir := "../rules/single_criterion/share_host_ipc/not_allow_share_host_ipc"
	testRuleConversion(t, ruleDir)
}

func TestConvertShareHostPIDRule(t *testing.T) {
	ruleDir := "../rules/single_criterion/share_host_pid/not_allow_share_host_pid"
	testRuleConversion(t, ruleDir)
}

func TestConvertShareHostNetworkRule(t *testing.T) {
	ruleDir := "../rules/single_criterion/share_host_network/not_allow_share_host_network"
	testRuleConversion(t, ruleDir)
}
