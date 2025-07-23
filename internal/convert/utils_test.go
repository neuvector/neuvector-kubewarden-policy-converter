//nolint:testpackage // will refactor this test to use testify
package convert

import (
	"reflect"
	"testing"
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
			if got != tt.want {
				t.Errorf("convertToRegexPattern(%q) = %q; want %q", tt.input, got, tt.want)
			}
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
			if (err != nil) != tt.wantErr {
				t.Errorf("parseValuesToList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseValuesToList() = %v, want %v", got, tt.want)
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
			if (err != nil) != tt.wantErr {
				t.Errorf("parseValuesToMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseValuesToMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_normalizeOpName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"=", "equal"},
		{"!regex", "notregex"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeOpName(tt.input)
			if got != tt.want {
				t.Errorf("normalizeOpName(%q) = %q; want %q", tt.input, got, tt.want)
			}
		})
	}
}

func Test_parseCommaSeparatedString(t *testing.T) {
	input := "nginx, redis,  alpine "
	want := []interface{}{"nginx", "redis", "alpine"}

	got := parseCommaSeparatedString(input)

	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseCommaSeparatedString(%q) = %v; want %v", input, got, want)
	}
}
