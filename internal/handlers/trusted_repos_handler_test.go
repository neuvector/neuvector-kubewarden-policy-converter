package handlers

import (
	"testing"

	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"

	"github.com/stretchr/testify/require"
)

func TestBuildTrustedReposPolicySettings(t *testing.T) {
	handler := NewTrustedReposHandler()

	tests := []struct {
		name             string
		criteria         []*nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			name: "grouped image registry set to true",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleImageRegistry,
					Op:    nvdata.CriteriaOpContainsAny,
					Value: "docker.io,quay.io",
				},
			},
			expectedSettings: []byte(`{"registries":{"reject":["docker.io","quay.io"]}}`),
		},
		{
			name: "grouped run as privileged set to false",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleImage,
					Op:    nvdata.CriteriaOpContainsAny,
					Value: "nginx,redis",
				},
				{
					Name:  RuleImageRegistry,
					Op:    nvdata.CriteriaOpNotContainsAny,
					Value: "docker.io,quay.io",
				},
			},
			expectedSettings: []byte(
				`{"registries":{"allow":["docker.io","quay.io"]},"images":{"reject":["nginx","redis"]}}`,
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildPolicySettings(tt.criteria)
			require.JSONEq(t, string(tt.expectedSettings), string(generatedSettings))
			require.Equal(t, tt.expectedError, err)
		})
	}
}
