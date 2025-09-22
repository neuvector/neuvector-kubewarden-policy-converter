package handlers

import (
	"testing"

	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
)

func TestEnvVarPolicySettingsConversion(t *testing.T) {
	handler := NewEnvVarHandler()

	tests := []struct {
		testCaseName     string
		inputCriteria    []*nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			testCaseName: "env var contains all specified values",
			inputCriteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleEnvVars,
					Op:    nvdata.CriteriaOpContainsAll,
					Value: "foo,bar",
				},
			},
			expectedSettings: []byte(
				`{"criteria":"doesNotContainAllOf","values":["foo","bar"]}`,
			),
		},
		{
			testCaseName: "env var contains any specified value",
			inputCriteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleEnvVars,
					Op:    nvdata.CriteriaOpContainsAny,
					Value: "foo,bar",
				},
			},
			expectedSettings: []byte(
				`{"criteria":"doesNotContainAnyOf","values":["foo","bar"]}`,
			),
		},
		{
			testCaseName: "env var contains values other than specified",
			inputCriteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleEnvVars,
					Op:    nvdata.CriteriaOpContainsOtherThan,
					Value: "foo,bar",
				},
			},
			expectedSettings: []byte(
				`{"criteria":"doesNotContainOtherThan","values":["foo","bar"]}`,
			),
		},
		{
			testCaseName: "env var does not contain any specified value",
			inputCriteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleEnvVars,
					Op:    nvdata.CriteriaOpNotContainsAny,
					Value: "foo,bar",
				},
			},
			expectedSettings: []byte(
				`{"criteria":"containsAnyOf","values":["foo","bar"]}`,
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.testCaseName, func(t *testing.T) {
			generatedSettings, err := handler.BuildPolicySettings(tt.inputCriteria)
			require.JSONEq(t, string(tt.expectedSettings), string(generatedSettings))
			require.Equal(t, tt.expectedError, err)
		})
	}
}
