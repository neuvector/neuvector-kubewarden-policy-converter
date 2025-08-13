package handlers

import (
	"strconv"
	"testing"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"

	"github.com/stretchr/testify/require"
)

func TestGetBoolValue(t *testing.T) {
	handler := NewHostNamespaceHandler()

	tests := []struct {
		name          string
		value         string
		expected      bool
		expectedError error
	}{
		{
			name:          "parse true string to boolean",
			value:         "true",
			expected:      false,
			expectedError: nil,
		},
		{
			name:          "parse false string to boolean",
			value:         "false",
			expected:      true,
			expectedError: nil,
		},
		{
			name:          "handle invalid boolean string",
			value:         "invalid",
			expected:      false,
			expectedError: &strconv.NumError{Func: "ParseBool", Num: "invalid", Err: strconv.ErrSyntax},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := handler.getBoolValue(tt.value)
			require.Equal(t, tt.expected, actual)
			require.Equal(t, tt.expectedError, err)
		})
	}
}

func TestBuildHostNamespacePolicySettings(t *testing.T) {
	handler := NewHostNamespaceHandler()

	tests := []struct {
		name             string
		criterion        *nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			name: "IPC sharing set to true",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleShareIPC,
				Op:    nvdata.CriteriaOpEqual,
				Value: "true",
			},
			expectedSettings: []byte(`{"allow_host_ipc":false,"allow_host_network":true,"allow_host_pid":true}`),
		},
		{
			name: "Network sharing set to true",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleShareNetwork,
				Op:    nvdata.CriteriaOpEqual,
				Value: "true",
			},
			expectedSettings: []byte(`{"allow_host_ipc":true,"allow_host_network":false,"allow_host_pid":true}`),
		},
		{
			name: "PID sharing set to true",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleSharePID,
				Op:    nvdata.CriteriaOpEqual,
				Value: "true",
			},
			expectedSettings: []byte(`{"allow_host_ipc":true,"allow_host_network":true,"allow_host_pid":false}`),
		},
		{
			name: "PID sharing set to false",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  RuleSharePID,
				Op:    nvdata.CriteriaOpEqual,
				Value: "false",
			},
			expectedSettings: []byte(`{"allow_host_ipc":true,"allow_host_network":true,"allow_host_pid":true}`),
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

func TestBuildHostNamespaceGroupedPolicySettings(t *testing.T) {
	handler := NewHostNamespaceHandler()

	tests := []struct {
		name             string
		criteria         []*nvapis.RESTAdmRuleCriterion
		expectedSettings []byte
		expectedError    error
	}{
		{
			name: "IPC sharing set to true",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleShareIPC,
					Op:    nvdata.CriteriaOpEqual,
					Value: "true",
				},
				{
					Name:  RuleShareNetwork,
					Op:    nvdata.CriteriaOpEqual,
					Value: "true",
				},
			},
			expectedSettings: []byte(`{"allow_host_ipc":false,"allow_host_network":false,"allow_host_pid":true}`),
		},
		{
			name: "IPC sharing set to true",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleShareIPC,
					Op:    nvdata.CriteriaOpEqual,
					Value: "true",
				},
				{
					Name:  RuleShareNetwork,
					Op:    nvdata.CriteriaOpEqual,
					Value: "true",
				},
				{
					Name:  RuleSharePID,
					Op:    nvdata.CriteriaOpEqual,
					Value: "true",
				},
			},
			expectedSettings: []byte(`{"allow_host_ipc":false,"allow_host_network":false,"allow_host_pid":false}`),
		},
		{
			name: "IPC sharing set to true",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleShareIPC,
					Op:    nvdata.CriteriaOpEqual,
					Value: "false",
				},
				{
					Name:  RuleShareNetwork,
					Op:    nvdata.CriteriaOpEqual,
					Value: "false",
				},
				{
					Name:  RuleSharePID,
					Op:    nvdata.CriteriaOpEqual,
					Value: "false",
				},
			},
			expectedSettings: []byte(`{"allow_host_ipc":true,"allow_host_network":true,"allow_host_pid":true}`),
		},
		{
			name: "Network sharing set to true",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  RuleShareNetwork,
					Op:    nvdata.CriteriaOpEqual,
					Value: "true",
				},
			},
			expectedSettings: []byte(`{"allow_host_ipc":true,"allow_host_network":false,"allow_host_pid":true}`),
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
