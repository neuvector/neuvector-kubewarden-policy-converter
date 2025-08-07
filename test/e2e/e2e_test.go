package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/convert"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	ModeProtect     = "protect"
	PolicyServer    = "default"
	BackgroundAudit = true
	OutputFile      = "output.yaml"
	ExpectedPolicy  = "policy.yaml"
)

// verifyWithKwctl verifies the output policy with kwctl,
// pass resources should be allowed, deny resources should be denied.
func verifyWithKwctl(t *testing.T, config *Config) {
	t.Helper()
	passResources := config.Pass
	denyResources := config.Deny

	for _, resource := range passResources {
		resourcePath := filepath.Join(config.TestWorkspace, resource)
		allowed, err := runKwctl(resourcePath, OutputFile)
		require.NoError(t, err, "error running kwctl for resource %s: %s", resource, err)
		assert.True(t, allowed, "resource %s should be allowed", resource)
	}

	for _, resource := range denyResources {
		resourcePath := filepath.Join(config.TestWorkspace, resource)
		allowed, err := runKwctl(resourcePath, OutputFile)
		require.NoError(t, err)
		assert.False(t, allowed, "resource %s should be denied", resource)
	}
}

// verifyWithYaml verifies the output policy with the expected policy.
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
	config, err := loadConfig(ruleDir)
	require.NoError(t, err)
	rule, err := loadRule(ruleDir)
	require.NoError(t, err)

	converter := convert.NewRuleConverter(share.ConversionConfig{
		Mode:            ModeProtect,
		PolicyServer:    PolicyServer,
		BackgroundAudit: BackgroundAudit,
		OutputFile:      OutputFile,
		Verbose:         false,
	})

	err = converter.Convert(rule)
	require.NoError(t, err)
	defer os.Remove(OutputFile)

	verifyWithYaml(t, ruleDir)

	if config.RunKwctl {
		verifyWithKwctl(t, config)
	}
}

func TestAdmissionRuleConversion(t *testing.T) {
	rulesDir := "../rules/"

	filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if hasReqRuleErr := hasRequiredRuleFiles(path); hasReqRuleErr != nil {
				//nolint:nilerr // Skip directories without required files
				return nil // Skip directories without required files
			}
			testRuleConversion(t, path)
			return nil
		}

		return nil
	})
}
