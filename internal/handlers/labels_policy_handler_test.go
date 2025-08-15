package handlers

import (
	"testing"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
)

func TestBuildLabelsPolicySettings(t *testing.T) {
	handler := NewLabelsPolicyHandler()

	tests := []struct {
		name             string
		criterion        *nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			name: "env var contains all",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleLabels,
				Op:    nvdata.CriteriaOpContainsAll,
				Value: "foo,bar",
			},
			expectedSettings: []byte(
				`{"criteria":"doesNotContainAllOf","values":["foo","bar"]}`,
			),
		},
		{
			name: "env var contains any",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleLabels,
				Op:    nvdata.CriteriaOpContainsAny,
				Value: "foo,bar",
			},
			expectedSettings: []byte(
				`{"criteria":"doesNotContainAnyOf","values":["foo","bar"]}`,
			),
		},
		{
			name: "env var contains other than",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleLabels,
				Op:    nvdata.CriteriaOpContainsOtherThan,
				Value: "foo,bar",
			},
			expectedSettings: []byte(
				`{"criteria":"containsOtherThan","values":["foo","bar"]}`,
			),
		},
		{
			name: "env var not contains any",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleLabels,
				Op:    nvdata.CriteriaOpNotContainsAny,
				Value: "foo,bar",
			},
			expectedSettings: []byte(
				`{"criteria":"containsAnyOf","values":["foo","bar"]}`,
			),
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

func TestBuildLabelsPolicyGroupedPolicySettings(t *testing.T) {
	handler := NewLabelsPolicyHandler()

	tests := []struct {
		name             string
		criteria         []*nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			name: "env var contains all",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleLabels,
					Op:    nvdata.CriteriaOpContainsAll,
					Value: "foo,bar",
				},
			},
			expectedSettings: []byte(
				`{"criteria":"doesNotContainAllOf","values":["foo","bar"]}`,
			),
		},
		{
			name: "env var contains all",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleLabels,
					Op:    nvdata.CriteriaOpContainsAny,
					Value: "foo,bar",
				},
			},
			expectedSettings: []byte(
				`{"criteria":"doesNotContainAnyOf","values":["foo","bar"]}`,
			),
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
