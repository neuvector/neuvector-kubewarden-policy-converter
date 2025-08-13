package handlers

import (
	"testing"

	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
)

func TestBuildEnvVarSecretPolicySettings(t *testing.T) {
	handler := NewEnvVarSecretHandler()

	tests := []struct {
		name             string
		criterion        *nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			name: "run as privileged set to true",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleEnvVarSecret,
				Op:    nvdata.CriteriaOpEqual,
				Value: "false",
			},
			expectedSettings: []byte(`{}`),
		},
		{
			name: "run as privileged set to false",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleEnvVarSecret,
				Op:    nvdata.CriteriaOpEqual,
				Value: "false",
			},
			expectedSettings: []byte(`{}`), // will also be empty, view it as a disable env secret policy
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildPolicySettings(tt.criterion)
			require.NoError(t, err)

			require.Equal(t, tt.expectedSettings, generatedSettings)
			require.Equal(t, tt.expectedError, err)
		})
	}
}

func TestBuildEnvVarSecretGroupedPolicySettings(t *testing.T) {
	handler := NewEnvVarSecretHandler()

	tests := []struct {
		name             string
		criteria         []*nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			name: "grouped run as privileged set to true",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleEnvVarSecret,
					Op:    nvdata.CriteriaOpEqual,
					Value: "false",
				},
			},
			expectedSettings: []byte(`{}`),
		},
		{
			name: "grouped run as privileged set to false",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleEnvVarSecret,
					Op:    nvdata.CriteriaOpEqual,
					Value: "false",
				},
			},
			expectedSettings: []byte(`{}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildGroupedPolicySettings(tt.criteria)
			require.NoError(t, err)

			require.Equal(t, tt.expectedSettings, generatedSettings)
			require.Equal(t, tt.expectedError, err)
		})
	}
}
