/*
Copyright (c) 2025 SUSE LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package convert

import (
	"encoding/json"
	"fmt"
	"strings"

	nvdata "github.com/neuvector/neuvector/share"
)

func normalizeOpName(input string) string {
	if input == nvdata.CriteriaOpEqual {
		return "equal"
	}

	if input == nvdata.CriteriaOpNotRegex {
		return "notregex"
	}

	return input
}

func parseCommaSeparatedString(input string) []interface{} {
	parts := strings.Split(input, ",")
	result := make([]interface{}, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		result = append(result, trimmed)
	}
	return result
}

func convertToRegexPattern(value string) string {
	if !strings.ContainsAny(value, "?*") {
		return fmt.Sprintf("^%s$", value)
	}

	cleanValue := strings.ReplaceAll(value, ".", "\\.")
	cleanValue = strings.ReplaceAll(cleanValue, "?", ".")
	cleanValue = strings.ReplaceAll(cleanValue, "*", ".*")

	return fmt.Sprintf("^%s$", cleanValue)
}

func parseValuesToList(input string) (string, error) {
	if strings.TrimSpace(input) == "" {
		return "[]", nil
	}

	values := strings.Split(input, ",")
	var result []string

	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		result = append(result, convertToRegexPattern(value))
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("failed to marshal list to JSON: %w", err)
	}

	return string(jsonBytes), nil
}

func parseValuesToMap(input string) (string, error) {
	pairs := strings.Split(input, ",")
	result := make(map[string]string)
	maxSplitParts := 2

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, nvdata.CriteriaOpEqual, maxSplitParts)
		key := strings.TrimSpace(parts[0])

		if key == "" {
			return "", fmt.Errorf("parseValuesToMap: empty key found in input: %q", pair)
		}

		if len(parts) == 1 {
			// Only key present, treat as "key": ".*"
			result[key] = ".*"
		} else {
			value := convertToRegexPattern(strings.TrimSpace(parts[1]))
			result[key] = value
		}
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("failed to marshal result to JSON: %w", err)
	}

	return string(jsonBytes), nil
}
