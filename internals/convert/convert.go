/*
Copyright 2025.

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
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
	"github.com/olekukonko/tablewriter"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

type ConversionConfig struct {
	OutputFile      string
	PolicyServer    string
	BackgroundAudit bool
}

const (
	MsgStatusOk   = "Ok"
	MsgStatusSkip = "Skip"

	MsgNeuVectorRuleOnly         = "NeuVector environment only rule"
	MsgOnlyDenyRuleSupported     = `Only "deny" rule supported`
	MsgRuleConvertedSuccessfully = "Rule converted successfully"
	MsgUnsupportedRuleCriteria   = "Unsupported criteria"
	MsgRuleParsingError          = "Failed to parse rule"
	MsgRuleGenerateKWPoilcyError = "Failed to generate Kubewarden poilcy"
)

// Define a struct to store the rule parsing result with unexported fields
type ruleParsingResult struct {
	id     string
	status string
	notes  string
}

func ProcessRules(input io.Reader, config ConversionConfig) error {
	ruleObj, err := parseAdmissionRules(input)
	if err != nil {
		return fmt.Errorf("failed to parse NeuVector Admission rules: %w", err)
	}

	var allYAMLs []string
	var results []ruleParsingResult

	for _, rule := range ruleObj.Rules {
		result, yamlStr := processSingleRule(rule, config)
		results = append(results, result)
		if yamlStr != "" {
			allYAMLs = append(allYAMLs, yamlStr)
		}
	}

	if err := outputYAML(config.OutputFile, allYAMLs); err != nil {
		return err
	}

	renderResultsTable(results)
	return nil
}

func processSingleRule(rule *nvapis.RESTAdmissionRule, config ConversionConfig) (ruleParsingResult, string) {
	idStr := strconv.FormatUint(uint64(rule.ID), 10)

	if rule.ID < 1000 {
		return ruleParsingResult{id: idStr, status: MsgStatusSkip, notes: MsgNeuVectorRuleOnly}, ""
	}

	if !isSupportedRule(rule) {
		return ruleParsingResult{id: idStr, status: MsgStatusSkip, notes: MsgUnsupportedRuleCriteria}, ""
	}

	useGroupType, err := shouldUsePolicyGroup(rule)
	if err != nil {
		// fmt.Printf("failed to check if we should use policy group: %v\n", err)
		return ruleParsingResult{id: idStr, status: MsgStatusSkip, notes: MsgRuleParsingError}, ""
	}

	var policy interface{}
	if useGroupType {
		policy, err = generatePolicyGroup(rule, config)
	} else {
		policy, err = generateClusterAdmissionPolicy(rule, config)
	}

	if err != nil {
		return ruleParsingResult{id: idStr, status: MsgStatusSkip, notes: MsgRuleGenerateKWPoilcyError}, ""
	}

	yamlBytes, err := yaml.Marshal(policy)
	if err != nil {
		return ruleParsingResult{id: idStr, status: MsgStatusSkip, notes: "YAML marshal error"}, ""
	}

	return ruleParsingResult{id: idStr, status: MsgStatusOk, notes: MsgRuleConvertedSuccessfully}, string(yamlBytes)
}

func outputYAML(outputFile string, yamls []string) error {
	output := strings.Join(yamls, "\n---\n")

	if outputFile != "" {
		err := os.WriteFile(outputFile, []byte(output), 0600)
		if err != nil {
			return fmt.Errorf("failed to write to output file %s: %w", outputFile, err)
		}
	} else {
		log.Println(output)
		log.Println("---")
	}
	return nil
}

func renderResultsTable(results []ruleParsingResult) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetColWidth(50)
	table.SetHeader([]string{"ID", "STATUS", "NOTES"})
	for _, result := range results {
		table.Append([]string{result.id, result.status, result.notes})
	}
	table.Render()
}

func shouldUsePolicyGroup(rule *nvapis.RESTAdmissionRule) (bool, error) {
	count := 0
	for _, criterion := range rule.Criteria {
		if criterion.Name != nvdata.CriteriaKeyNamespace {
			count++
		}

		// Certain criteria may result in multiple policies being generated.
		// In such cases, we should group them under a policy group.
		// For example, "pspCompliance" criteria can each produce multiple policies.
		mappingType, err := getMappingType(criterion.Name)
		if err != nil {
			return false, err
		}

		if mappingType == mappingType1toMany {
			return true, nil
		}
	}
	return count > 1, nil
}

// Generate a ClusterAdmissionPolicy CR
// Use cases:
//  1. When there is only one criterion and it has a 1-to-1 mapping to a policy.
//     (This is determined using the supported_matrix.)
//  2. When there are two criteria, and one of them is a namespace criterion.
func generateClusterAdmissionPolicy(rule *nvapis.RESTAdmissionRule, config ConversionConfig) (*policiesv1.ClusterAdmissionPolicy, error) {
	policy := policiesv1.ClusterAdmissionPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterAdmissionPolicy",
			APIVersion: "policies.kubewarden.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("neuvector-rule-%d-conversion", rule.ID),
		},
		Spec: policiesv1.ClusterAdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				MatchConditions: []admissionregistrationv1.MatchCondition{},
				Rules:           buildRules(),
				PolicyServer:    config.PolicyServer,
				BackgroundAudit: config.BackgroundAudit,
			},
		},
	}

	for _, criterion := range rule.Criteria {
		// Use a matchCondition to filter by namespace only when there is more than one criterion.
		// If there's only one namespace criterion, namespace matching can be handled directly in the policy.
		if criterion.Name == nvdata.CriteriaKeyNamespace && len(rule.Criteria) > 1 {
			selector, err := getNamespaceSelector(criterion)
			if err != nil {
				return nil, err
			}

			policy.Spec.PolicySpec.MatchConditions = []admissionregistrationv1.MatchCondition{
				{
					Name:       "namespaceSelector",
					Expression: selector,
				},
			}

			continue
		}

		module, err := getModule(criterion.Name)
		if err != nil {
			return nil, err
		}
		policy.Spec.PolicySpec.Module = module

		settings, err := buildPolicySettings(criterion)
		if err != nil {
			return nil, err
		}
		policy.Spec.PolicySpec.Settings = runtime.RawExtension{
			Raw: settings,
		}
	}

	return &policy, nil
}

// Generate a ClusterAdmissionPolicyGroup CR
func generatePolicyGroup(rule *nvapis.RESTAdmissionRule, config ConversionConfig) (*policiesv1.ClusterAdmissionPolicyGroup, error) {
	group := policiesv1.ClusterAdmissionPolicyGroup{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterAdmissionPolicyGroup",
			APIVersion: "policies.kubewarden.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("neuvector-rule-%d-conversion", rule.ID),
		},
	}

	group.Spec = policiesv1.ClusterAdmissionPolicyGroupSpec{
		ClusterPolicyGroupSpec: policiesv1.ClusterPolicyGroupSpec{
			GroupSpec: policiesv1.GroupSpec{
				Message:         fmt.Sprintf("violate NeuVector rule (id=%d), comment %s", rule.ID, rule.Comment),
				Rules:           buildRules(),
				PolicyServer:    config.PolicyServer,
				BackgroundAudit: config.BackgroundAudit,
			},
			Policies: policiesv1.PolicyGroupMembersWithContext{},
		},
	}

	// For each criterion, generate the corresponding policy or policies.
	for i, criterion := range rule.Criteria {
		if criterion.Name == nvdata.CriteriaKeyNamespace {
			selector, err := getNamespaceSelector(criterion)
			if err != nil {
				return nil, err
			}

			group.Spec.GroupSpec.MatchConditions = []admissionregistrationv1.MatchCondition{
				{
					Name:       "namespaceSelector",
					Expression: selector,
				},
			}
			continue
		}

		generateMembersFunc, err := getGenerateMembersFunc(criterion.Name)
		if err != nil {
			return nil, err
		}

		groupMembers, err := generateMembersFunc(criterion)
		if err != nil {
			return nil, err
		}

		for j, member := range groupMembers {
			policyName := fmt.Sprintf("%s_policy_%d_%d", criterion.Name, i, j)
			group.Spec.Policies[policyName] = member
		}
	}

	// Build logical expressions based on the defined policies.
	var conditions []string
	for key := range group.Spec.Policies {
		conditions = append(conditions, fmt.Sprintf("%s()", key))
	}
	conditionStr := strings.Join(conditions, " && ")
	group.Spec.GroupSpec.Expression = conditionStr

	return &group, nil
}

func buildRules() []admissionregistrationv1.RuleWithOperations {
	return []admissionregistrationv1.RuleWithOperations{
		{
			Operations: []admissionregistrationv1.OperationType{
				admissionregistrationv1.Create,
			},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods"},
			},
		},
		{
			Operations: []admissionregistrationv1.OperationType{
				admissionregistrationv1.Create,
				admissionregistrationv1.Update,
			},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{"apps"},
				APIVersions: []string{"v1"},
				Resources:   []string{"deployments", "replicasets", "daemonsets", "statefulsets"},
			},
		},
		{
			Operations: []admissionregistrationv1.OperationType{
				admissionregistrationv1.Create,
				admissionregistrationv1.Update,
			},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{"batch"},
				APIVersions: []string{"v1"},
				Resources:   []string{"jobs", "cronjobs"},
			},
		},
	}
}

func getNamespaceSelector(criterion *nvapis.RESTAdmRuleCriterion) (string, error) {
	if criterion == nil {
		return "", errors.New("criterion is nil")
	}

	userData, err := parseValuesToList(criterion.Value)
	if err != nil {
		return "", fmt.Errorf("failed to parse criterion values: %w", err)
	}

	switch criterion.Op {
	case "containsAny":
		return fmt.Sprintf("!has(request.namespace) || !%s.exists(pattern, request.namespace.matches(pattern))", userData), nil
	case "notContainsAny":
		return fmt.Sprintf("!has(request.namespace) || %s.exists(pattern, request.namespace.matches(pattern))", userData), nil
	default:
		return "", fmt.Errorf("unsupported operator: %s", criterion.Op)
	}
}

func generatePspComplianceMembers(_ *nvapis.RESTAdmRuleCriterion) ([]policiesv1.PolicyGroupMemberWithContext, error) {
	var members []policiesv1.PolicyGroupMemberWithContext

	yamlFiles := map[string]string{
		"templates/host_namespaces_psp.yaml": policyHostNamespacesPSP,
		fmt.Sprintf("templates/%s_%s.yaml", nvdata.CriteriaKeyRunAsPrivileged, normalizeOpName(nvdata.CriteriaOpEqual)):     policyPodPrivileged,
		fmt.Sprintf("templates/%s_%s.yaml", nvdata.CriteriaKeyRunAsRoot, normalizeOpName(nvdata.CriteriaOpEqual)):           policyUserGroupPSP,
		fmt.Sprintf("templates/%s_%s.yaml", nvdata.CriteriaKeyAllowPrivEscalation, normalizeOpName(nvdata.CriteriaOpEqual)): policyAllowPrivEscalation,
	}

	for yamlFile, module := range yamlFiles {
		yamlObj, err := readYAML(yamlFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read or parse YAML: %w", err)
		}

		settings, err := json.Marshal(yamlObj)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal object: %w", err)
		}

		member := policiesv1.PolicyGroupMemberWithContext{
			PolicyGroupMember: policiesv1.PolicyGroupMember{
				Module: module,
				Settings: runtime.RawExtension{
					Raw: settings,
				},
			},
		}

		members = append(members, member)
	}

	return members, nil
}

func buildPolicySettings(criterion *nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	yamlFile := fmt.Sprintf("templates/%s_%s.yaml", criterion.Name, normalizeOpName(criterion.Op))
	yamlObj, err := readYAML(yamlFile)
	if err != nil {
		return nil, fmt.Errorf("unsupported or missing template for %s %s: %w", criterion.Name, criterion.Op, err)
	}

	injectPolicySettingFunc, err := getPolicySettingFunc(criterion.Name)
	if err != nil {
		return nil, err
	}

	if injectPolicySettingFunc != nil {
		if err := injectPolicySettingFunc(criterion, yamlObj); err != nil {
			return nil, err
		}
	}

	rawBytes, err := json.Marshal(yamlObj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal object: %w", err)
	}
	return rawBytes, nil
}

func generatePolicyGroupMember(criterion *nvapis.RESTAdmRuleCriterion) ([]policiesv1.PolicyGroupMemberWithContext, error) {
	module, err := getModule(criterion.Name)
	if err != nil {
		return nil, err
	}

	settings, err := buildPolicySettings(criterion)
	if err != nil {
		return nil, err
	}

	policy := policiesv1.PolicyGroupMemberWithContext{
		PolicyGroupMember: policiesv1.PolicyGroupMember{
			Module: module,
			Settings: runtime.RawExtension{
				Raw: settings,
			},
		},
	}

	return []policiesv1.PolicyGroupMemberWithContext{policy}, nil
}

func injectTrustedRepoPolicySetting(criterion *nvapis.RESTAdmRuleCriterion, yamlObj map[string]interface{}) error {
	objKeyMap := map[string]string{
		nvdata.CriteriaKeyImageRegistry: "registries",
		nvdata.CriteriaKeyImage:         "images",
	}

	objKey, ok := objKeyMap[criterion.Name]
	if !ok {
		return fmt.Errorf("unknown criterion name: %s", criterion.Name)
	}

	// Ensure the section exists and is a map
	section, _ := yamlObj[objKey].(map[string]interface{})
	if section == nil {
		section = make(map[string]interface{})
		yamlObj[objKey] = section
	}

	// Determine the action based on the operator
	actionMap := map[string]string{
		nvdata.CriteriaOpContainsAny:    "reject",
		nvdata.CriteriaOpNotContainsAny: "allow",
	}

	action, ok := actionMap[criterion.Op]
	if !ok {
		return fmt.Errorf("unknown operator: %s", criterion.Op)
	}

	section[action] = parseCommaSeparatedString(criterion.Value)
	return nil
}

func injectCelPolicySetting(criterion *nvapis.RESTAdmRuleCriterion, yamlObj map[string]interface{}) error {
	valueType, err := getCriterionValueType(criterion.Name)
	if err != nil {
		return fmt.Errorf("failed to get value type for criterion %s: %w", criterion.Name, err)
	}

	if valueType != "list" && valueType != "map" {
		return nil
	}

	varList, _ := yamlObj["variables"].([]interface{})
	if varList == nil {
		varList = []interface{}{}
	}

	newVar := map[string]interface{}{
		"name": "userConfig",
	}

	// Populate the expression based on valueType
	var expr interface{}
	switch valueType {
	case "list":
		expr, err = parseValuesToList(criterion.Value)
		if err != nil {
			return fmt.Errorf("failed to parse list value for criterion %s: %w", criterion.Name, err)
		}
	case "map":
		expr, err = parseValuesToMap(criterion.Value)
		if err != nil {
			return fmt.Errorf("failed to parse map value for criterion %s: %w", criterion.Name, err)
		}
	}

	newVar["expression"] = expr
	yamlObj["variables"] = append(varList, newVar)

	return nil
}
