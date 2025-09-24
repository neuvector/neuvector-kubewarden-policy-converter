package policy

import (
	"testing"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	"github.com/stretchr/testify/require"
)

func TestGeneratePolicyName(t *testing.T) {
	builder := BaseBuilder{}

	tests := []struct {
		name     string
		rule     *nvapis.RESTAdmissionRule
		expected string
	}{
		{
			name: "rule with comment",
			rule: &nvapis.RESTAdmissionRule{
				Comment: "test comment",
			},
			expected: "neuvector-rule-0-conversion",
		},
		{
			name: "rule without comment",
			rule: &nvapis.RESTAdmissionRule{
				ID: 123,
			},
			expected: "neuvector-rule-123-conversion",
		},
		{
			name: "rule with comment and spaces",
			rule: &nvapis.RESTAdmissionRule{
				Comment: "test comment with spaces",
				ID:      123,
			},
			expected: "neuvector-rule-123-conversion",
		},
		{
			name: "rule with comment and spaces",
			rule: &nvapis.RESTAdmissionRule{
				Comment: "test comment with spaces 787483 UIUJ",
				ID:      123,
			},
			expected: "neuvector-rule-123-conversion",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := builder.generatePolicyName(tt.rule)
			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestGetRulelMode(t *testing.T) {
	builder := BaseBuilder{}

	tests := []struct {
		name     string
		rule     *nvapis.RESTAdmissionRule
		config   share.ConversionConfig
		expected string
	}{
		{
			name: "CLI mode overrides rule mode",
			rule: &nvapis.RESTAdmissionRule{
				RuleMode: "protect",
			},
			config: share.ConversionConfig{
				Mode: "monitor",
			},
			expected: "monitor",
		},
		{
			name: "CLI mode used when rule mode is not set",
			rule: &nvapis.RESTAdmissionRule{
				RuleMode: "",
			},
			config: share.ConversionConfig{
				Mode: "monitor",
			},
			expected: "monitor",
		},
		{
			name: "Rule mode used when CLI mode is not provided",
			rule: &nvapis.RESTAdmissionRule{
				RuleMode: "protect",
			},
			config: share.ConversionConfig{
				Mode: "",
			},
			expected: "protect",
		},
		{
			name: "Default mode used when both CLI and rule modes are not set",
			rule: &nvapis.RESTAdmissionRule{
				RuleMode: "",
			},
			config: share.ConversionConfig{
				Mode: "",
			},
			expected: "protect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := builder.getRulelMode(tt.rule, tt.config)
			require.Equal(t, tt.expected, actual)
		})
	}
}
