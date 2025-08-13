package handlers

import (
	"testing"

	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"

	"github.com/stretchr/testify/require"
)

func TestBuildAllowPrivilegedEscalationPolicySettings(t *testing.T) {
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
