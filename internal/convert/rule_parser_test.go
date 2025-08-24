package convert

import (
	"testing"

	nvapis "github.com/neuvector/neuvector/controller/api"
	"github.com/stretchr/testify/require"
)

func compareRulesIgnoreFields(
	t *testing.T,
	expected, actual *nvapis.RESTAdmissionRule,
	ignoreFields ...string,
) {
	// Ignore specified fields in the expected rule that are not used for conversion
	ignoreFieldsInRule(expected, ignoreFields...)
	require.Equal(t, expected, actual)
}

func ignoreFieldsInRule(rule *nvapis.RESTAdmissionRule, fields ...string) {
	for _, field := range fields {
		switch field {
		case "category":
			rule.Category = ""
		case "cfg_type":
			rule.CfgType = ""
		case "critical":
			rule.Critical = false
		}
	}
}

func TestRuleParser(t *testing.T) {
	yamlPath := "../../test/fixtures/rule_parser/share_ipc_net_pid.yaml"
	expectedJSONPath := "../../test/fixtures/rule_parser/share_ipc_net_pid.json"

	yamlParser := NewRuleParser(yamlPath)
	yamlRules, err := yamlParser.ParseRules()
	require.NoError(t, err)
	require.NotNil(t, yamlRules)

	jsonParser := NewRuleParser(expectedJSONPath)
	jsonRules, err := jsonParser.ParseRules()
	require.NoError(t, err)
	require.NotNil(t, jsonRules)

	require.Len(t, yamlRules.Rules, len(jsonRules.Rules))

	for i := range jsonRules.Rules {
		compareRulesIgnoreFields(t,
			jsonRules.Rules[i],
			yamlRules.Rules[i],
			"category", "cfg_type", "critical")
	}
}
