package handlers

import (
	"testing"

	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"

	"github.com/stretchr/testify/require"
)

func TestBuildPodPrivilegedPolicySettings(t *testing.T) {
	handler := NewPodPrivilegedHandler()

	tests := []struct {
		name             string
		criterion        *nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			name: "run as privileged set to true",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleRunAsPrivileged,
				Op:    nvdata.CriteriaOpEqual,
				Value: "true",
			},
			expectedSettings: []byte(`{}`),
		},
		{
			name: "run as privileged set to false",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleRunAsPrivileged,
				Op:    nvdata.CriteriaOpEqual,
				Value: "false",
			},
			expectedSettings: []byte(`{}`),
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

func TestBuildPodPrivilegedGroupedPolicySettings(t *testing.T) {
	handler := NewPodPrivilegedHandler()

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
					Name:  RuleRunAsPrivileged,
					Op:    nvdata.CriteriaOpEqual,
					Value: "true",
				},
			},
			expectedSettings: []byte(`{}`),
		},
		{
			name: "grouped run as privileged set to false",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleRunAsPrivileged,
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
