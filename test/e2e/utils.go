package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	kwctlExecPath    = "../../bin/kwctl"
	kwctlTimeout     = 30 * time.Second
	converterTimeout = 30 * time.Second
	PolicyServer     = "default"
	BackgroundAudit  = true
	ConverterBinary  = "../../bin/nvrules2kw"
)

// Config is the configuration for a rule.
type Config struct {
	Description   string   `json:"description"`
	TestWorkspace string   `json:"testWorkspace"`
	RunKwctl      bool     `json:"runKwctl"` // Whether to run kwctl to verify the rule
	Accept        []string `json:"accept"`   // List of files that should accept after run kwctl
	Reject        []string `json:"reject"`   // List of files that should deny after run kwctl
}

type kwctlResponse struct {
	UID     string `json:"uid"`
	Allowed bool   `json:"allowed"`
	Status  *struct {
		Message string `json:"message,omitempty"`
	} `json:"status,omitempty"`
}

// verifyWithKwctl verifies the output policy with kwctl,
// accept resources should be allowed, deny resources should be denied.
func verifyWithKwctl(t *testing.T, config *Config, outputPath string) {
	t.Helper()
	for _, testCase := range []struct {
		accept    bool
		resources []string
	}{
		{true, config.Accept},
		{false, config.Reject},
	} {
		for _, resource := range testCase.resources {
			resourcePath := filepath.Join(config.TestWorkspace, resource)
			allowed, err := runKwctl(resourcePath, outputPath)
			require.NoError(t, err, "error running kwctl for resource %s: %s", resource, err)
			if testCase.accept {
				assert.True(t, allowed, "resource %s should be accepted", resource)
			} else {
				assert.False(t, allowed, "resource %s should be denied", resource)
			}
		}
	}
}

func loadConfig(ruleDir string) (*Config, error) {
	configPath := filepath.Join(ruleDir, "config.json")
	if _, err := os.Stat(configPath); err != nil {
		return nil, err
	}
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var config Config
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func runKwctl(resourcePath, policyPath string) (bool, error) {
	if _, err := os.Stat(resourcePath); err != nil {
		return false, fmt.Errorf("resource file does not exist: %w", err)
	}
	if _, err := os.Stat(policyPath); err != nil {
		return false, fmt.Errorf("policy file does not exist: %w", err)
	}

	// Create context with timeout for security
	ctx, cancel := context.WithTimeout(context.Background(), kwctlTimeout)
	defer cancel()

	scaffoldCmd := exec.CommandContext(ctx, kwctlExecPath, "scaffold", "admission-request",
		"--operation", "CREATE",
		"--object", resourcePath,
	)

	output, err := scaffoldCmd.Output()
	if err != nil {
		return false, fmt.Errorf("kwctl scaffold failed: %w", err)
	}

	tempFile, err := os.CreateTemp("", "admission-request-*.json")
	if err != nil {
		return false, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())

	err = os.WriteFile(tempFile.Name(), output, 0600)
	if err != nil {
		return false, fmt.Errorf("failed to write temp file: %w", err)
	}

	//nolint:gosec // File paths are validated and temp file is safely created
	kwctlCmd := exec.CommandContext(ctx, kwctlExecPath, "run", "-r", tempFile.Name(), policyPath)
	output, err = kwctlCmd.Output()
	if err != nil {
		return false, fmt.Errorf("kwctl run failed: %w", err)
	}

	var response kwctlResponse
	err = json.Unmarshal(output, &response)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal kwctl response: %w", err)
	}
	return response.Allowed, nil
}

func runConverterBinary(rule, policies string) error {
	// Create context with timeout for security
	ctx, cancel := context.WithTimeout(context.Background(), converterTimeout)
	defer cancel()

	args := []string{
		"convert",
		"--output", policies,
		"--mode", "protect",
		"--policyserver", PolicyServer,
		"--backgroundaudit", strconv.FormatBool(BackgroundAudit),
		rule,
	}

	cmd := exec.CommandContext(ctx, ConverterBinary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("converter binary failed: %w, output: %s", err, string(output))
	}

	return nil
}

func testRuleConversion(t *testing.T, ruleDir string) {
	t.Helper()
	config, err := loadConfig(ruleDir)
	require.NoError(t, err)

	rulePath := filepath.Join(ruleDir, "rule.json")
	outputPath := filepath.Join(ruleDir, "output.yaml")

	err = runConverterBinary(rulePath, outputPath)
	require.NoError(t, err)
	defer os.Remove(outputPath)

	if config.RunKwctl {
		verifyWithKwctl(t, config, outputPath)
	}
}
