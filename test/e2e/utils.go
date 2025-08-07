package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	kwctlExecPath = "../../bin/kwctl"
	kwctlTimeout  = 30 * time.Second
)

// Config is the configuration for a rule.
type Config struct {
	Description   string   `json:"description"`
	TestWorkspace string   `json:"testWorkspace"`
	RunKwctl      bool     `json:"runKwctl"` // Whether to run kwctl to verify the rule
	Pass          []string `json:"pass"`     // List of files that should pass after run kwctl
	Deny          []string `json:"deny"`     // List of files that should deny after run kwctl
}

type kwctlResponse struct {
	UID     string `json:"uid"`
	Allowed bool   `json:"allowed"`
	Status  *struct {
		Message string `json:"message,omitempty"`
	} `json:"status,omitempty"`
}

func hasRequiredRuleFiles(path string) error {
	configPath := filepath.Join(path, "config.json")
	rulePath := filepath.Join(path, "rule.json")

	// Check if both files exist
	if _, err := os.Stat(configPath); err != nil {
		return err
	}
	if _, err := os.Stat(rulePath); err != nil {
		return err
	}

	return nil
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

func loadRule(ruleDir string) (io.Reader, error) {
	rulePath := filepath.Join(ruleDir, "rule.json")
	return os.Open(rulePath)
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
