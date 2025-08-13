package handlers

import (
	"testing"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"

	"github.com/stretchr/testify/require"
)

func TestBuildAllowPrivilegedEscalationPolicySettings(t *testing.T) {
	handler := NewAllowPrivilegedEscalationHandler()

	tests := []struct {
		name             string
		criterion        *nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			name: "allow privileged escalation set to true",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleAllowPrivilegedEscalation,
				Op:    nvdata.CriteriaOpEqual,
				Value: "true",
			},
			expectedSettings: []byte(`{"default_allow_privilege_escalation":true}`),
		},
		{
			name: "allow privileged escalation set to false",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleAllowPrivilegedEscalation,
				Op:    nvdata.CriteriaOpEqual,
				Value: "false",
			},
			expectedSettings: []byte(
				`{"default_allow_privilege_escalation":true}`,
			), // Ensure converter only set the default setting true
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildPolicySettings(tt.criterion)
			require.NoError(t, err)

			convertedSettings, err := share.ConvertBytesToJSON(generatedSettings)
			require.NoError(t, err)
			expectedSettings, err := share.ConvertBytesToJSON(tt.expectedSettings)
			require.NoError(t, err)

			require.Equal(t, expectedSettings, convertedSettings)
			require.Equal(t, tt.expectedError, err)
		})
	}
}

func TestBuildAllowPrivilegedEscalationGroupedPolicySettings(t *testing.T) {
	handler := NewAllowPrivilegedEscalationHandler()

	tests := []struct {
		name             string
		criteria         []*nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			name: "allow privileged escalation set to true",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleAllowPrivilegedEscalation,
					Op:    nvdata.CriteriaOpEqual,
					Value: "true",
				},
			},
			expectedSettings: []byte(`{"default_allow_privilege_escalation":true}`),
		},
		{
			name: "allow privileged escalation set to false",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleAllowPrivilegedEscalation,
					Op:    nvdata.CriteriaOpEqual,
					Value: "false",
				},
			},
			expectedSettings: []byte(
				`{"default_allow_privilege_escalation":true}`,
			), // Ensure converter only set the default setting true
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildGroupedPolicySettings(tt.criteria)
			require.NoError(t, err)

			convertedSettings, err := share.ConvertBytesToJSON(generatedSettings)
			require.NoError(t, err)
			expectedSettings, err := share.ConvertBytesToJSON(tt.expectedSettings)
			require.NoError(t, err)

			require.Equal(t, expectedSettings, convertedSettings)
			require.Equal(t, tt.expectedError, err)
		})
	}
}
