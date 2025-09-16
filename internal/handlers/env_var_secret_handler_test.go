package handlers

import (
	"fmt"
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
			name: "envVarSecrets set to false",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleEnvVarSecret,
				Op:    nvdata.CriteriaOpEqual,
				Value: "false",
			},
			expectedSettings: []byte(`{}`),
		},
		{
			name: "envVarSecrets set to true",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleEnvVarSecret,
				Op:    nvdata.CriteriaOpEqual,
				Value: "true",
			},
			expectedError: fmt.Errorf("envVarSecrets supports only false value, got: %s", "true"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildPolicySettings([]*nvapis.RESTAdmRuleCriterion{tt.criterion})
			require.Equal(t, tt.expectedError, err)
			require.Equal(t, tt.expectedSettings, generatedSettings)
		})
	}
}
