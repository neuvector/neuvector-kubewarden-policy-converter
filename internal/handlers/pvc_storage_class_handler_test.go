package handlers

import (
	"testing"

	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"

	"github.com/stretchr/testify/require"
)

func TestPVCStorageClassPolicySettingsGeneration(t *testing.T) {
	handler := NewPVCStorageClassHandler()

	tests := []struct {
		name             string
		criteria         []*nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			name: "contains any storage classes specified",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleStorageClass,
					Op:    nvdata.CriteriaOpContainsAny,
					Value: "foo,bar",
				},
			},
			expectedSettings: []byte(`{"deniedStorageClasses":["foo","bar"]}`),
		},
		{
			name: "not contains any storage classes specified",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleStorageClass,
					Op:    nvdata.CriteriaOpNotContainsAny,
					Value: "foo,bar",
				},
			},
			expectedSettings: []byte(`{"allowedStorageClasses":["foo","bar"]}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildPolicySettings(tt.criteria)
			require.NoError(t, err)

			require.Equal(t, tt.expectedSettings, generatedSettings)
			require.Equal(t, tt.expectedError, err)
		})
	}
}
