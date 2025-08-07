package handlers

import (
	"strconv"
	"testing"

	nvapis "github.com/neuvector/neuvector/controller/api"
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

func TestBuildPolicySettings(t *testing.T) {
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
				Name:  ShareIPC,
				Op:    "=",
				Value: "true",
			},
			expectedSettings: []byte(`{"allow_host_ipc":false,"allow_host_network":true,"allow_host_pid":true}`),
		},
		{
			name: "Network sharing set to true",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  ShareNetwork,
				Op:    "=",
				Value: "true",
			},
			expectedSettings: []byte(`{"allow_host_ipc":true,"allow_host_network":false,"allow_host_pid":true}`),
		},
		{
			name: "PID sharing set to true",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  SharePID,
				Op:    "=",
				Value: "true",
			},
			expectedSettings: []byte(`{"allow_host_ipc":true,"allow_host_network":true,"allow_host_pid":false}`),
		},
		{
			name: "PID sharing set to false",
			criterion: &nvapis.RESTAdmRuleCriterion{
				Name:  SharePID,
				Op:    "=",
				Value: "false",
			},
			expectedSettings: []byte(`{"allow_host_ipc":true,"allow_host_network":true,"allow_host_pid":true}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildPolicySettings(tt.criterion)
			require.Equal(t, tt.expectedSettings, generatedSettings)
			require.Equal(t, tt.expectedError, err)
		})
	}
}

func TestBuildGroupedPolicySettings(t *testing.T) {
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
					Name:  ShareIPC,
					Op:    "=",
					Value: "true",
				},
				{
					Name:  ShareNetwork,
					Op:    "=",
					Value: "true",
				},
			},
			expectedSettings: []byte(`{"allow_host_ipc":false,"allow_host_network":false,"allow_host_pid":true}`),
		},
		{
			name: "IPC sharing set to true",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  ShareIPC,
					Op:    "=",
					Value: "true",
				},
				{
					Name:  ShareNetwork,
					Op:    "=",
					Value: "true",
				},
				{
					Name:  SharePID,
					Op:    "=",
					Value: "true",
				},
			},
			expectedSettings: []byte(`{"allow_host_ipc":false,"allow_host_network":false,"allow_host_pid":false}`),
		},
		{
			name: "IPC sharing set to true",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  ShareIPC,
					Op:    "=",
					Value: "false",
				},
				{
					Name:  ShareNetwork,
					Op:    "=",
					Value: "false",
				},
				{
					Name:  SharePID,
					Op:    "=",
					Value: "false",
				},
			},
			expectedSettings: []byte(`{"allow_host_ipc":true,"allow_host_network":true,"allow_host_pid":true}`),
		},
		{
			name: "Network sharing set to true",
			criteria: []*nvapis.RESTAdmRuleCriterion{
				{
					Name:  ShareNetwork,
					Op:    "=",
					Value: "true",
				},
			},
			expectedSettings: []byte(`{"allow_host_ipc":true,"allow_host_network":false,"allow_host_pid":true}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generatedSettings, err := handler.BuildGroupedPolicySettings(tt.criteria)
			require.Equal(t, tt.expectedSettings, generatedSettings)
			require.Equal(t, tt.expectedError, err)
		})
	}
}
