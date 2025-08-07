package convert

import (
	"testing"

	nvdata "github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
)

// TODO: refactor this test to use testify
func Test_convertToRegexPattern(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"No Wildcards", "abc", "^abc$"},
		{"With Asterisk", "a*", "^a.*$"},
		{"With Question Mark", "a?.c", "^a.\\.c$"},
		{"With Star and Dot", "*.svc.local", "^.*\\.svc\\.local$"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertToRegexPattern(tt.input)
			require.Equal(t, tt.want, got, "input: %q", tt.input)
		})
	}
}

func Test_parseValuesToList(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			"Single Value",
			"nginx",
			`["^nginx$"]`,
			false,
		},
		{
			"Multiple Values",
			"nginx,redis",
			`["^nginx$","^redis$"]`,
			false,
		},
		{
			"Values with Wildcards",
			"nginx*,redis?",
			`["^nginx.*$","^redis.$"]`,
			false,
		},
		{
			"Empty String",
			"",
			`[]`,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseValuesToList(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}
		})
	}
}

func Test_parseValuesToMap(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			"Single Key-Value Pair",
			"app=nginx",
			`{"app":"^nginx$"}`,
			false,
		},
		{
			"Multiple Key-Value Pairs",
			"app=nginx,env=prod",
			`{"app":"^nginx$","env":"^prod$"}`,
			false,
		},
		{
			"Key With No Value",
			"role",
			`{"role":".*"}`,
			false,
		},
		{
			"Key With Empty Value",
			"team=",
			`{"team":"^$"}`,
			false,
		},
		{
			"Empty Key Should Error",
			"=value",
			``,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseValuesToMap(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}
		})
	}
}

func Test_normalizeOpName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{nvdata.CriteriaOpEqual, "equal"},
		{"!regex", "notregex"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeOpName(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_parseCommaSeparatedString(t *testing.T) {
	input := "nginx, redis,  alpine "
	want := []interface{}{"nginx", "redis", "alpine"}

	got := parseCommaSeparatedString(input)

	require.Equal(t, want, got)
}
