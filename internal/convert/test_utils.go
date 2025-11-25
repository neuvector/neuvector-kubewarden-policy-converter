package convert

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	ModeProtect     = "protect"
	PolicyServer    = "default"
	BackgroundAudit = true

	ExpectedPolicy = "policy.yaml"
	OutputFile     = "output.yaml"
)

// VerifyWithYaml verifies the output policy with the expected policy.
func verifyWithYaml(t *testing.T, ruleDir string) {
	expectedPolicyPath := filepath.Join(ruleDir, ExpectedPolicy)
	expectedPolicy, err := os.ReadFile(expectedPolicyPath)
	require.NoError(t, err)

	actualPolicy, err := os.ReadFile(OutputFile)
	require.NoError(t, err)

	assert.YAMLEq(t, string(expectedPolicy), string(actualPolicy))
}

func testRuleConversion(t *testing.T, ruleDir string) {
	t.Helper()

	converter := NewRuleConverter(share.ConversionConfig{
		Mode:               ModeProtect,
		PolicyServer:       PolicyServer,
		BackgroundAudit:    BackgroundAudit,
		OutputFile:         OutputFile,
		VulReportNamespace: "default",
		Platform:           "amd64",
	})

	rulePath := filepath.Join(ruleDir, "rule.json")
	err := converter.Convert(context.Background(), rulePath)
	require.NoError(t, err)
	defer os.Remove(OutputFile)

	verifyWithYaml(t, ruleDir)
}

func testRuleConversionWithFail(t *testing.T, ruleDir string, mode string) {
	t.Helper()

	converter := NewRuleConverter(share.ConversionConfig{
		Mode:            mode,
		PolicyServer:    PolicyServer,
		BackgroundAudit: BackgroundAudit,
		OutputFile:      OutputFile,
	})

	rulePath := filepath.Join(ruleDir, "rule.json")
	err := converter.Convert(context.Background(), rulePath)

	require.Error(t, err)
	require.NoFileExists(t, OutputFile)
}
