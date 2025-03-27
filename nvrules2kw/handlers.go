package main

import (
	"fmt"
	"strings"

	"github.com/suse-security/nvrules2kw/nvapis"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	UserConfigKey = "userConfig"
)

type OutputTypeFunction func(string) string

func HandleImagePolicy(settings map[string]interface{}, criterion *nvapis.RESTAdmRuleCriterion) error {
	// Validate settings structure
	nestedSettings, ok := settings["settings"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("unable to find 'settings' in the provided map")
	}

	// Clean up unwanted keys
	for _, key := range []string{"rules", "backgroundAudit"} {
		delete(settings, key)
	}

	// Determine the correct path based on the criterion
	var nestedPath string
	switch criterion.Name {
	case "image":
		nestedPath = "images.reject"
	case "imageRegistry":
		nestedPath = "registries.reject"
	default:
		return fmt.Errorf("unsupported criterion name: %s", criterion.Name)
	}

	// Adjust path if operation is 'notContainsAny'
	if criterion.Op == "notContainsAny" {
		nestedPath = strings.Replace(nestedPath, "reject", "allow", 1)
	}

	// Set the values
	data := strings.Split(criterion.Value, ",")
	if err := SetNestedStringSlice(nestedSettings, nestedPath, data); err != nil {
		return fmt.Errorf("failed to set nested string slice: %w", err)
	}

	return nil
}

func SetNestedStringSlice(yamlData map[string]interface{}, key string, newValues []string) error {
	keys := strings.Split(key, ".")

	interfaceValues := make([]interface{}, len(newValues))
	for i, v := range newValues {
		interfaceValues[i] = v
	}

	if err := unstructured.SetNestedSlice(yamlData, interfaceValues, keys...); err != nil {
		return fmt.Errorf("failed to set nested field: %w", err)
	}
	return nil
}

func HandleGenericPolicy(settings map[string]interface{}, criterion *nvapis.RESTAdmRuleCriterion) error {
	// Remove unwanted keys
	delete(settings, "mutating")
	delete(settings, "rules")
	delete(settings, "backgroundAudit")

	// in generic scenario, we don't need to update the settings.
	return nil
}

func HandleCELPolicyValueList(settings map[string]interface{}, criterion *nvapis.RESTAdmRuleCriterion) error {
	return handleCELPolicy(settings, criterion, parseValuesToList)
}

func HandleCELPolicyValueMap(settings map[string]interface{}, criterion *nvapis.RESTAdmRuleCriterion) error {
	return handleCELPolicy(settings, criterion, parseValuesToMap)
}

func handleCELPolicy(settings map[string]interface{}, criterion *nvapis.RESTAdmRuleCriterion, formatter OutputTypeFunction) error {
	nestedSettings, ok := settings["settings"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("unable to find 'settings' in the provided map")
	}

	// Remove unwanted keys
	delete(settings, "mutating")
	delete(settings, "rules")
	delete(settings, "backgroundAudit")

	variables, ok := nestedSettings["variables"].([]interface{})
	if !ok {
		return fmt.Errorf("unable to find 'variables' in 'settings'")
	}

	// Iterate through variables and update
	for i, v := range variables {
		if variable, ok := v.(map[string]interface{}); ok && variable["name"] == UserConfigKey {
			// variable["expression"] = parseValuesToMap(criterion.Value)
			variable["expression"] = formatter(criterion.Value)
			variables[i] = variable
			nestedSettings["variables"] = variables
			return nil
		}
	}

	return nil
}

func parseValuesToMap(input string) string {
	pairs := strings.Split(input, ",")
	result := make(map[string]string)

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 1 {
			// Case where only key is present, treat as "key": ".*"
			key := strings.TrimSpace(parts[0])
			result[key] = ".*"
			continue
		}

		key := strings.TrimSpace(parts[0])
		result[key] = convertToRegexPattern(strings.TrimSpace(parts[1]))
	}

	// Build JSON-like output
	var builder strings.Builder
	builder.WriteString("{")
	first := true
	for k, v := range result {
		if !first {
			builder.WriteString(", ")
		}
		first = false
		builder.WriteString(fmt.Sprintf("\"%s\": \"%s\"", k, v))
	}
	builder.WriteString("}")

	return builder.String()
}

func parseValuesToList(input string) string {
	values := strings.Split(input, ",")
	var result []string

	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		result = append(result, fmt.Sprintf("\"%s\"", convertToRegexPattern(value)))
	}

	return fmt.Sprintf("[%s]", strings.Join(result, ", "))
}

func convertToRegexPattern(value string) string {
	if !strings.ContainsAny(value, "?*") {
		return fmt.Sprintf("^%s$", value)
	}
	cleanValue := strings.Replace(value, ".", "\\.", -1)
	cleanValue = strings.Replace(cleanValue, "?", ".", -1)
	cleanValue = strings.Replace(cleanValue, "*", ".*", -1)
	return fmt.Sprintf("^%s$", cleanValue)
}
