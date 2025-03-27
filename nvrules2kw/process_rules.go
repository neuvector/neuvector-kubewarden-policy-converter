package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/suse-security/nvrules2kw/nvapis"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

type RuleHandler func(map[string]interface{}, *nvapis.RESTAdmRuleCriterion) error

var handlers = map[string]RuleHandler{
	"labels":              HandleCELPolicyValueMap,
	"envVars":             HandleCELPolicyValueMap,
	"annotations":         HandleCELPolicyValueMap,
	"allowPrivEscalation": HandleGenericPolicy,
	"runAsPrivileged":     HandleGenericPolicy,
	"runAsRoot":           HandleGenericPolicy,
	"shareIpcWithHost":    HandleGenericPolicy,
	"shareNetWithHost":    HandleGenericPolicy,
	"sharePidWithHost":    HandleGenericPolicy,
	"namespace":           HandleCELPolicyValueList,
	"user":                HandleCELPolicyValueList,
	"userGroups":          HandleCELPolicyValueList,
	"envVarSecrets":       HandleGenericPolicy,
	"image":               HandleImagePolicy,
	"imageRegistry":       HandleImagePolicy,
	"pspCompliance":       HandleGenericPolicy,
}

func ProcessRules(input io.Reader) error {
	ruleObj, err := ParseJSON(input)
	if err != nil {
		return fmt.Errorf("failed to parse JSON file: %w", err)
	}

	for _, rule := range ruleObj.Rules {
		// user defined rules start from ID 1000
		if rule.ID < 1000 {
			continue
		}

		if !IsSupportedRule(rule) {
			continue
		}

		policies, err := GeneratePolicies(rule)
		if err != nil {
			return fmt.Errorf("failed to generate policies: %w", err)
		}

		policyMessage := fmt.Sprintf("Policy from NeuVector rule ID %d. %s", rule.ID, rule.Comment)
		if err := MergePolicies(policies, policyMessage, "templates/base.yaml"); err != nil {
			return fmt.Errorf("failed to apply policies: %w", err)
		}
	}
	return nil
}

func GeneratePolicies(rule *nvapis.RESTAdmissionRule) (map[string]interface{}, error) {
	policies := make(map[string]interface{})

	for _, criterion := range rule.Criteria {
		//debug
		if criterion.Name == "namespace" {
			debugme()
		}

		records, err := generatePolicies(criterion)
		if err != nil {
			return nil, fmt.Errorf("failed to generate policies: %w", err)
		}

		// one criteria	can have multiple policies
		for _, itemMap := range records {
			for key, value := range itemMap {
				policies[key] = value
			}
		}
	}

	return policies, nil
}

func IsSupportedRule(rule *nvapis.RESTAdmissionRule) bool {
	// only deny rule is supported
	if rule.RuleType != nvapis.ValidatingDenyRuleType {
		return false
	}

	for _, c := range rule.Criteria {
		if !supportedMatrix[c.Name][c.Op] {
			return false
		}
	}
	return true
}

// ParseJSON reads JSON data from an io.Reader and unmarshals it into RESTAdmissionRulesData
func ParseJSON(reader io.Reader) (*nvapis.RESTAdmissionRulesData, error) {
	var data nvapis.RESTAdmissionRulesData
	if err := json.NewDecoder(reader).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}
	return &data, nil
}

func generatePspCompliancePolicy(criterion *nvapis.RESTAdmRuleCriterion) ([]map[string]map[string]interface{}, error) {
	var data []map[string]map[string]interface{}

	yamlFiles := []string{
		"templates/runAsPrivileged.yaml",
		"templates/runAsRoot_equal.yaml",
		"templates/allowPrivEscalation_equal.yaml",
		"templates/host_namespaces_psp.yaml",
	}

	for idx, yamlFile := range yamlFiles {
		yamlObj, err := readYAML(yamlFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read or parse YAML: %w", err)
		}

		u := &unstructured.Unstructured{Object: yamlObj}

		settings, found, err := unstructured.NestedMap(u.Object, "spec")
		if err != nil || !found {
			return nil, fmt.Errorf("failed to extract spec.settings: %w", err)
		}

		handler := HandleGenericPolicy
		if err := handler(settings, criterion); err != nil {
			return nil, err
		}

		policyName := fmt.Sprintf("policy_%s_%d_%s", criterion.Name, idx, normalizeOpName(criterion.Op))

		data = append(data, map[string]map[string]interface{}{
			policyName: settings,
		})
	}

	return data, nil
}

func generatePolicies(criterion *nvapis.RESTAdmRuleCriterion) ([]map[string]map[string]interface{}, error) {
	var data []map[string]map[string]interface{}

	// pspCompliance, this will generate 6 policies
	if criterion.Name == "pspCompliance" {
		return generatePspCompliancePolicy(criterion)
	}

	yamlFile := fmt.Sprintf("templates/%s_%s.yaml", criterion.Name, normalizeOpName(criterion.Op))
	yamlObj, err := readYAML(yamlFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read or parse YAML: %w", err)
	}

	u := &unstructured.Unstructured{Object: yamlObj}

	settings, found, err := unstructured.NestedMap(u.Object, "spec")
	if err != nil || !found {
		return nil, fmt.Errorf("failed to extract spec.settings: %w", err)
	}

	handler, exists := handlers[criterion.Name]
	if !exists {
		return nil, fmt.Errorf("handler not found, unsupported criteria : %s", criterion.Name)
	}

	if err := handler(settings, criterion); err != nil {
		return nil, err
	}

	policyName := fmt.Sprintf("policy_%s_%s", criterion.Name, normalizeOpName(criterion.Op))

	data = append(data, map[string]map[string]interface{}{
		policyName: settings,
	})

	return data, nil
}

func MergePolicies(policies map[string]interface{}, policyMessage string, baseFilePath string) error {
	baseYAML, err := readYAML(baseFilePath)
	if err != nil {
		return err
	}

	base := &unstructured.Unstructured{Object: baseYAML}
	if err := unstructured.SetNestedField(base.Object, policies, "spec", "policies"); err != nil {
		return fmt.Errorf("failed to insert policies: %w", err)
	}

	if err := unstructured.SetNestedField(base.Object, getPolicyKeys(policies), "spec", "expression"); err != nil {
		return fmt.Errorf("failed to update expression: %w", err)
	}

	// Modify spec.message
	if err := unstructured.SetNestedField(base.Object, policyMessage, "spec", "message"); err != nil {
		return fmt.Errorf("failed to update message: %w", err)
	}

	finalYAML, err := yaml.Marshal(base.Object)
	if err != nil {
		return fmt.Errorf("failed to marshal final YAML: %w", err)
	}

	fmt.Println(string(finalYAML))
	fmt.Println("---")
	return nil
}

func readYAML(filePath string) (map[string]interface{}, error) {
	data, err := yamlFiles.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read YAML file %s: %w", filePath, err)
	}
	var yamlObj map[string]interface{}
	if err := yaml.Unmarshal(data, &yamlObj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML %s: %w", filePath, err)
	}
	return yamlObj, nil
}

func getPolicyKeys(policies map[string]interface{}) string {
	keys := make([]string, 0, len(policies))
	for key := range policies {
		keys = append(keys, key+"()")
	}
	// return strings.Join(keys, " && ")
	return strings.Join(keys, " || ")
}

func normalizeOpName(input string) string {
	if input == "=" {
		return "equal"
	}

	if input == "!regex" {
		return "notregex"
	}

	return input
}

func debugme() {
	// fmt.Println("debug")
}
