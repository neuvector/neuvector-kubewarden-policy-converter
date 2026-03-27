package handlers

import (
	"testing"

	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
)

func TestBuildImageCvePolicySettings(t *testing.T) {
	testNamespace := "sbomscanner"
	testPlatform := "arm64"
	handler := NewImageCVEHandler(testNamespace, testPlatform)

	tests := []struct {
		name             string
		criterion        []*nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			name: "high CVE count is greater than or equal to 10",
			criterion: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleHighCVECount,
					Op:    nvdata.CriteriaOpBiggerEqualThan,
					Value: "10",
				},
			},
			expectedSettings: []byte(`{
				"vulnerabilityReportNamespace": "sbomscanner",
				"platform": {
					"arch": "arm64",
					"os": "linux"
				},
				"maxSeverity": {
					"high": {
						"total": 9
					}
				}
			}`),
		},
		{
			name: "medium CVE count is greater than or equal to 5",
			criterion: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleMedCVECount,
					Op:    nvdata.CriteriaOpBiggerEqualThan,
					Value: "5",
				},
			},
			expectedSettings: []byte(`{
				"vulnerabilityReportNamespace": "sbomscanner",
				"platform": {
					"arch": "arm64",
					"os": "linux"
				},
				"maxSeverity": {
					"medium": {
						"total": 4
					}
				}
			}`),
		},
		{
			name: "image scanned is set to true",
			criterion: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleImageScanned,
					Op:    nvdata.CriteriaOpEqual,
					Value: "true",
				},
			},
			expectedSettings: []byte(`{
				"vulnerabilityReportNamespace": "sbomscanner",
				"platform": {
					"arch": "arm64",
					"os": "linux"
				},
				"ignoreMissingVulnerabilityReport": true
			}`),
		},
		{
			name: "high CVE count is greater than or equal to 5 and medium CVE count is greater than or equal to 5",
			criterion: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleHighCVECount,
					Op:    nvdata.CriteriaOpBiggerEqualThan,
					Value: "15",
				},
				{
					Name:  RuleMedCVECount,
					Op:    nvdata.CriteriaOpBiggerEqualThan,
					Value: "5",
				},
			},
			expectedSettings: []byte(`{
				"vulnerabilityReportNamespace": "sbomscanner",
				"platform": {
					"arch": "arm64",
					"os": "linux"
				},
				"maxSeverity": {
					"high": {
						"total": 14
					},
					"medium": {
						"total": 4
					}
				}
			}`),
		},
		{
			name: "CVE score count maps threshold from the criterion and max count from the subcriteria",
			criterion: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleCVEScoreCount,
					Op:    nvdata.CriteriaOpBiggerEqualThan,
					Value: "7",
					SubCriteria: []*nvapis.RESTAdmRuleCriterion{
						{
							Name:  nvdata.SubCriteriaCount,
							Op:    nvdata.CriteriaOpBiggerEqualThan,
							Value: "3",
						},
					},
				},
			},
			expectedSettings: []byte(`{
				"vulnerabilityReportNamespace": "sbomscanner",
				"platform": {
					"arch": "arm64",
					"os": "linux"
				},
				"cvssScore": {
					"threshold": 7,
					"maxCount": 2
				}
			}`),
		},
		{
			name: "CVE score count without subcriteria returns an error",
			criterion: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleCVEScoreCount,
					Op:    nvdata.CriteriaOpBiggerEqualThan,
					Value: "7",
				},
			},
			expectedError: fmt.Errorf("missing subcriteria for %s", RuleCVEScoreCount),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildPolicySettings(tt.criterion)
			require.Equal(t, tt.expectedError, err)
			if tt.expectedError != nil {
				require.Nil(t, generatedSettings)
				return
			}
			require.JSONEq(t, string(tt.expectedSettings), string(generatedSettings))
		})
	}
}
