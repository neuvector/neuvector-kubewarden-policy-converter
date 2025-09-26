package handlers

import (
	"testing"

	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
)

func TestBuildHighRiskServiceAccountPolicySettings(t *testing.T) {
	handler := NewHighRiskServiceAccountHandler()

	tests := []struct {
		name             string
		criterion        *nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			name: "saBindRiskyRole set to true",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleHighRiskServiceAccount,
				Op:    nvdata.CriteriaOpContainsAny,
				Value: "risky_role_any_action_rbac",
			},
			expectedSettings: []byte(
				`{
					"blockRules": [
						{
							"apiGroups": ["rbac.authorization.k8s.io"],
							"resources": ["roles", "rolebindings"],
							"verbs": ["*"]
						}
					]
				}`,
			),
		},
		{
			name: "saBindRiskyRole set to true",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleHighRiskServiceAccount,
				Op:    nvdata.CriteriaOpContainsAny,
				Value: "risky_role_view_secret,risky_role_any_action_workload",
			},
			expectedSettings: []byte(
				`{
					"blockRules": [
						{
							"apiGroups": [""],
							"resources": ["secrets"],
							"verbs": ["list", "get"]
						},
						{
							"apiGroups": [""],
							"resources": ["pods", "pods/log"],
							"verbs": ["*"]
						},
						{
							"apiGroups": ["apps"],
							"resources": ["deployments", "statefulsets", "daemonsets", "replicasets"],
							"verbs": ["*"]
						},
						{
							"apiGroups": ["batch"],
							"resources": ["jobs", "cronjobs"],
							"verbs": ["*"]
						},
						{
							"apiGroups": ["autoscaling"],
							"resources": ["horizontalpodautoscalers"],
							"verbs": ["*"]
						}
					]
				}`,
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildPolicySettings([]*nvapis.RESTAdmRuleCriterion{tt.criterion})
			require.Equal(t, tt.expectedError, err)
			require.JSONEq(t, string(tt.expectedSettings), string(generatedSettings))
		})
	}
}
