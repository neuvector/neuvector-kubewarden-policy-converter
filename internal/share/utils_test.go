package share

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractModuleName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "registry://ghcr.io/kubewarden/policies/host-namespaces-psp:v0.1.7_policy",
			expected: "host_namespaces_psp",
		},
		{
			input:    "ghcr.io/kubewarden/policies/host-namespaces-psp:v0.1.7",
			expected: "host_namespaces_psp",
		},
		{
			input:    "registry://ghcr.io/kubewarden/policies/host-namespaces-psp",
			expected: "host_namespaces_psp",
		},
		{
			input:    "ghcr.io/kubewarden/policies/host-namespaces-psp",
			expected: "host_namespaces_psp",
		},
		// edge cases
		{input: "foo/bar", expected: "bar"},
		{input: "foo", expected: "foo"},
		{input: "foo:bar", expected: "foo"},
		{input: "registry://foo", expected: "foo"},
	}

	for _, tc := range tests {
		output := ExtractModuleName(tc.input)
		require.Equal(t, tc.expected, output)
	}
}
