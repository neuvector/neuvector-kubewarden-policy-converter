package handlers

import (
	"testing"

	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
)

func TestBuildAnnotationsPolicySettings(t *testing.T) {
	handler := NewAnnotationsPolicyHandler()

	tests := []struct {
		name             string
		criterion        []*nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			name: "env var contains all",
			criterion: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleAnnotations,
					Op:    nvdata.CriteriaOpContainsAll,
					Value: "foo,bar",
				},
			},
			expectedSettings: []byte(
				`{"criteria":"doesNotContainAllOf","values":["foo","bar"]}`,
			),
		},
		{
			name: "env var contains any",
			criterion: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleAnnotations,
					Op:    nvdata.CriteriaOpContainsAny,
					Value: "foo,bar",
				},
			},
			expectedSettings: []byte(
				`{"criteria":"doesNotContainAnyOf","values":["foo","bar"]}`,
			),
		},
		{
			name: "env var contains other than",
			criterion: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleAnnotations,
					Op:    nvdata.CriteriaOpContainsOtherThan,
					Value: "foo,bar",
				},
			},
			expectedSettings: []byte(
				`{"criteria":"doesNotContainOtherThan","values":["foo","bar"]}`,
			),
		},
		{
			name: "env var not contains any",
			criterion: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleAnnotations,
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
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildPolicySettings(tt.criterion)
			require.JSONEq(t, string(tt.expectedSettings), string(generatedSettings))
			require.Equal(t, tt.expectedError, err)
		})
	}
}
