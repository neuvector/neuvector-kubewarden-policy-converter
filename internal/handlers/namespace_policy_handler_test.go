package handlers

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
)

func TestBuildNamespacesPolicySettings(t *testing.T) {
	handler := NewNamespacePolicyHandler()
	opts := cmp.Options{
		cmp.Transformer("trimSpace", strings.TrimSpace),
	}
	tests := []struct {
		name             string
		criterion        *nvapis.RESTAdmRuleCriterion
		expectedSettings map[string][]CELValidation
		expectedError    error
	}{
		{
			name: "namespace contains any - foo,bar,woo",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleNamespace,
				Op:    nvdata.CriteriaOpContainsAny,
				Value: "foo,bar,woo",
			},
			expectedSettings: map[string][]CELValidation{
				"validations": {
					{
						Expression: `has(object.metadata.namespace) && !(object.metadata.namespace in ["foo", "bar", "woo"])`,
						Message:    `Namespace must not be one of: "foo", "bar", "woo".`,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		var actualData map[string][]CELValidation
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildPolicySettings(tt.criterion)
			require.NoError(t, err)

			err = json.Unmarshal(generatedSettings, &actualData)
			require.NoError(t, err)

			diff := cmp.Diff(tt.expectedSettings, actualData, opts)
			require.Empty(t, diff)
		})
	}
}

func TestBuildNamespacesGroupedPolicySettings(t *testing.T) {
	handler := NewNamespacePolicyHandler()
	opts := cmp.Options{
		cmp.Transformer("trimSpace", strings.TrimSpace),
	}
	tests := []struct {
		name             string
		criteria         []*nvapis.RESTAdmRuleCriterion
		expectedSettings map[string][]CELValidation
		expectedError    error
	}{
		{
			name: "grouped namespace contains any - test1,test2,test3",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleNamespace,
					Op:    nvdata.CriteriaOpContainsAny,
					Value: "test1,test2,test3",
				},
			},
			expectedSettings: map[string][]CELValidation{
				"validations": {
					{
						Expression: `has(object.metadata.namespace) && !(object.metadata.namespace in ["test1", "test2", "test3"])`,
						Message:    `Namespace must not be one of: "test1", "test2", "test3".`,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		var actualData map[string][]CELValidation
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildGroupedPolicySettings(tt.criteria)
			require.NoError(t, err)

			err = json.Unmarshal(generatedSettings, &actualData)
			require.NoError(t, err)

			diff := cmp.Diff(tt.expectedSettings, actualData, opts)
			require.Empty(t, diff)
		})
	}
}
