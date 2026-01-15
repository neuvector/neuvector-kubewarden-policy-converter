package handlers

import (
	"testing"

	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"

	"github.com/stretchr/testify/require"
)

func TestBuildContainerResourcePolicySettings(t *testing.T) {
	handler := NewContainerResourceHandler()

	tests := []struct {
		name             string
		criteria         []*nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectError      bool
	}{
		{
			name: "resource limit with CPU and memory constraints",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleResourceLimit,
					Op:    "",
					Value: "",
					SubCriteria: []*nvapis.RESTAdmRuleCriterion{
						{
							Name:  "cpuLimit",
							Op:    nvdata.CriteriaOpLessEqualThan,
							Value: "3",
						},
						{
							Name:  "cpuRequest",
							Op:    nvdata.CriteriaOpBiggerThan,
							Value: "6",
						},
						{
							Name:  "memoryLimit",
							Op:    nvdata.CriteriaOpLessEqualThan,
							Value: "7516192768",
						},
						{
							Name:  "memoryRequest",
							Op:    nvdata.CriteriaOpBiggerThan,
							Value: "1520435200",
						},
					},
				},
			},
			expectedSettings: []byte(
				`{
					"cpu": {
						"minLimit": "3",
						"maxRequest": "6"
					},
					"memory": {
						"minLimit": "7516192768",
						"maxRequest": "1520435200"
					}
				}`,
			),
		},
		{
			name: "only CPU limit with <= operator",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleResourceLimit,
					Op:    "",
					Value: "",
					SubCriteria: []*nvapis.RESTAdmRuleCriterion{
						{
							Name:  "cpuLimit",
							Op:    nvdata.CriteriaOpLessEqualThan,
							Value: "4",
						},
					},
				},
			},
			expectedSettings: []byte(
				`{
					"cpu": {
						"minLimit": "4"
					}
				}`,
			),
		},
		{
			name: "only CPU request with > operator",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleResourceLimit,
					Op:    "",
					Value: "",
					SubCriteria: []*nvapis.RESTAdmRuleCriterion{
						{
							Name:  "cpuRequest",
							Op:    nvdata.CriteriaOpBiggerThan,
							Value: "2",
						},
					},
				},
			},
			expectedSettings: []byte(
				`{
					"cpu": {
						"maxRequest": "2"
					}
				}`,
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildPolicySettings(tt.criteria)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.JSONEq(t, string(tt.expectedSettings), string(generatedSettings))
			}
		})
	}
}
