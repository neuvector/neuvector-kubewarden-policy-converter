package handlers

import (
	"testing"

	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"

	"github.com/stretchr/testify/require"
)

func TestBuildContainerRunningAsUserPolicySettings(t *testing.T) {
	handler := NewContainerRunningAsUserHandler()

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
					Name:  RuleRunAsRoot,
					Op:    nvdata.CriteriaOpEqual,
					Value: "true",
				},
			},
			expectedSettings: []byte(
				`{}`,
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildPolicySettings(tt.criteria)
			require.NoError(t, err)
			require.JSONEq(t, string(tt.expectedSettings), string(generatedSettings))
			require.Equal(t, tt.expectedError, err)
		})
	}
}
