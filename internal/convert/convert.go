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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

type ConversionConfig struct {
	OutputFile      string
	PolicyServer    string
	Mode            string
	BackgroundAudit bool
	matrix          *CriteriaMatrix
}

type RuleConverter struct {
	config ConversionConfig
}

func NewRuleConverter(config ConversionConfig) *RuleConverter {
	rc := &RuleConverter{config: config}
	rc.config.matrix = NewCriteriaMatrix(rc)
	return rc
}

const (
	MsgStatusOk   = "Ok"
	MsgStatusSkip = "Skip"

	MsgNeuVectorRuleOnly           = "NeuVector environment only rule"
	MsgOnlyDenyRuleSupported       = `Only "deny" rule supported`
	MsgRuleConvertedSuccessfully   = "Rule converted successfully"
	MsgUnsupportedRuleCriteria     = "Unsupported criteria"
	MsgUnsupportedCriteriaOperator = "Unsupported operator"
	MsgRuleParsingError            = "Failed to parse rule"
	MsgRuleGenerateKWPolicyError   = "Failed to generate Kubewarden poilcy"

	defaultColumnWidth = 50
)

// Policy stores the rule parsing result with unexported fields.
type Policy interface{}

type ruleParsingResult struct {
	id     uint32
	status string
	notes  string
	policy Policy
}

func (r *RuleConverter) ProcessRules(input io.Reader) error {
	admissionRules, err := parseAdmissionRules(input)
	if err != nil {
		return fmt.Errorf("failed to parse NeuVector Admission rules: %w", err)
	}

	var (
		results  []ruleParsingResult
		policies []Policy
	)

	for _, rule := range admissionRules.Rules {
		result := r.processSingleRule(rule)
		results = append(results, result)

		if result.policy != nil {
			policies = append(policies, result.policy)
		}
	}

	if len(policies) == 0 {
		return errors.New("no valid policies generated from the input rules")
	}

	// output all collected policies
	if err = r.outputPolicies(policies, r.config.OutputFile); err != nil {
		return fmt.Errorf("failed to write output YAML: %w", err)
	}

	err = r.renderResultsTable(results)
	if err != nil {
		return fmt.Errorf("failed to render results table: %w", err)
	}

	return nil
}

func (r *RuleConverter) ShowRules() error {
	return r.config.matrix.dumpSupportedCriteriaTable()
}

func (r *RuleConverter) processSingleRule(rule *nvapis.RESTAdmissionRule) ruleParsingResult {
	supported, reason := r.config.matrix.isSupportedRule(rule)
	if !supported {
		return ruleParsingResult{id: rule.ID, status: MsgStatusSkip, notes: reason}
	}

	useGroupType, err := r.requiresPolicyGroup(rule)
	if err != nil {
		note := fmt.Sprintf("%s: %v", MsgRuleParsingError, err)
		return ruleParsingResult{id: rule.ID, status: MsgStatusSkip, notes: note}
	}

	var policy Policy
	if useGroupType {
		policy, err = r.generatePolicyGroup(rule)
	} else {
		policy, err = r.generateClusterAdmissionPolicy(rule)
	}

	if err != nil {
		note := fmt.Sprintf("%s: %v", MsgRuleGenerateKWPolicyError, err)
		return ruleParsingResult{id: rule.ID, status: MsgStatusSkip, notes: note}
	}

	return ruleParsingResult{
		id:     rule.ID,
		status: MsgStatusOk,
		notes:  MsgRuleConvertedSuccessfully,
		policy: policy,
	}
}

func (r *RuleConverter) renderResultsTable(results []ruleParsingResult) error {
	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithConfig(tablewriter.Config{
			Row: tw.CellConfig{
				Formatting:   tw.CellFormatting{AutoWrap: tw.WrapNormal},
				Alignment:    tw.CellAlignment{Global: tw.AlignLeft},
				ColMaxWidths: tw.CellWidth{Global: defaultColumnWidth},
			},
		}),
	)
	table.Header([]string{"ID", "STATUS", "NOTES"})
	for _, result := range results {
		data := []string{
			strconv.FormatUint(uint64(result.id), 10),
			result.status,
			result.notes,
		}
		err := table.Append(data)
		if err != nil {
			return fmt.Errorf("failed to append data: %w", err)
		}
	}

	err := table.Render()
	if err != nil {
		return fmt.Errorf("failed to render table: %w", err)
	}

	return nil
}

func (r *RuleConverter) requiresPolicyGroup(rule *nvapis.RESTAdmissionRule) (bool, error) {
	count := 0
	for _, criterion := range rule.Criteria {
		if criterion.Name != nvdata.CriteriaKeyNamespace {
			count++
		}

		// Certain criteria may result in multiple policies being generated.
		// In such cases, we should group them under a policy group.
		// For example, "pspCompliance" criteria can each produce multiple policies.
		isOneToMany, err := r.config.matrix.IsOneToMany(criterion.Name)
		if err != nil {
			return false, err
		}

		if isOneToMany {
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
func (r *RuleConverter) generateClusterAdmissionPolicy(
	rule *nvapis.RESTAdmissionRule,
) (*policiesv1.ClusterAdmissionPolicy, error) {
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
				Mode:            policiesv1.PolicyMode(r.config.Mode),
				PolicyServer:    r.config.PolicyServer,
				BackgroundAudit: r.config.BackgroundAudit,
			},
		},
	}

	for _, criterion := range rule.Criteria {
		// Use a matchCondition to filter by namespace only when there is more than one criterion.
		// If there's only one namespace criterion, namespace matching can be handled directly in the policy.
		if criterion.Name == nvdata.CriteriaKeyNamespace && len(rule.Criteria) > 1 {
			selector, err := r.getNamespaceSelector(criterion)
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

		module, err := r.config.matrix.GetModule(criterion.Name)
		if err != nil {
			return nil, err
		}
		policy.Spec.PolicySpec.Module = module

		settings, err := r.buildPolicySettings(criterion)
		if err != nil {
			return nil, err
		}
		policy.Spec.PolicySpec.Settings = runtime.RawExtension{
			Raw: settings,
		}
	}

	return &policy, nil
}

// Generate a ClusterAdmissionPolicyGroup CR.
func (r *RuleConverter) generatePolicyGroup(
	rule *nvapis.RESTAdmissionRule,
) (*policiesv1.ClusterAdmissionPolicyGroup, error) {
	var (
		policies   = policiesv1.PolicyGroupMembersWithContext{}
		conditions []string
		matchConds []admissionregistrationv1.MatchCondition
	)

	// For each criterion, generate the corresponding policy or policies.
	for i, criterion := range rule.Criteria {
		// use MatchCondition for namespace criteria for better performance
		if criterion.Name == nvdata.CriteriaKeyNamespace {
			selector, err := r.getNamespaceSelector(criterion)
			if err != nil {
				return nil, err
			}

			matchConds = []admissionregistrationv1.MatchCondition{
				{
					Name:       "namespaceSelector",
					Expression: selector,
				},
			}
			continue
		}

		generateMembersFunc, err := r.config.matrix.GetGenerateMembersFunc(criterion.Name)
		if err != nil {
			return nil, err
		}

		groupMembers, err := generateMembersFunc(criterion)
		if err != nil {
			return nil, err
		}

		for j, member := range groupMembers {
			policyName := fmt.Sprintf("%s_policy_%d_%d", criterion.Name, i, j)
			policies[policyName] = member
			conditions = append(conditions, fmt.Sprintf("%s()", policyName))
		}
	}

	group := policiesv1.ClusterAdmissionPolicyGroup{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterAdmissionPolicyGroup",
			APIVersion: "policies.kubewarden.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("neuvector-rule-%d-conversion", rule.ID),
		},
		Spec: policiesv1.ClusterAdmissionPolicyGroupSpec{
			ClusterPolicyGroupSpec: policiesv1.ClusterPolicyGroupSpec{
				GroupSpec: policiesv1.GroupSpec{
					Message:         fmt.Sprintf("violate NeuVector rule (id=%d), comment %s", rule.ID, rule.Comment),
					Rules:           buildRules(),
					Mode:            policiesv1.PolicyMode(r.config.Mode),
					PolicyServer:    r.config.PolicyServer,
					BackgroundAudit: r.config.BackgroundAudit,
					MatchConditions: matchConds,
					Expression:      strings.Join(conditions, " && "),
				},
				Policies: policies,
			},
		},
	}

	return &group, nil
}

func (r *RuleConverter) buildPolicySettings(criterion *nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	yamlFile := fmt.Sprintf("templates/%s_%s.yaml", criterion.Name, normalizeOpName(criterion.Op))
	yamlObj, err := readEmbeddedTemplate(yamlFile)
	if err != nil {
		return nil, fmt.Errorf("unsupported or missing template for %s %s: %w", criterion.Name, criterion.Op, err)
	}

	injectPolicySettingFunc, err := r.config.matrix.GetPolicySettingFunc(criterion.Name)
	if err != nil {
		return nil, err
	}

	if injectPolicySettingFunc != nil {
		err = injectPolicySettingFunc(criterion, yamlObj)
		if err != nil {
			return nil, err
		}
	}

	rawBytes, err := json.Marshal(yamlObj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal object: %w", err)
	}
	return rawBytes, nil
}

func (r *RuleConverter) generatePolicyGroupMembers(
	criterion *nvapis.RESTAdmRuleCriterion,
) ([]policiesv1.PolicyGroupMemberWithContext, error) {
	module, err := r.config.matrix.GetModule(criterion.Name)
	if err != nil {
		return nil, err
	}

	settings, err := r.buildPolicySettings(criterion)
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

func (r *RuleConverter) injectTrustedRepoPolicySetting(
	criterion *nvapis.RESTAdmRuleCriterion,
	yamlObj map[string]interface{},
) error {
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

func (r *RuleConverter) injectCelPolicySetting(
	criterion *nvapis.RESTAdmRuleCriterion,
	yamlObj map[string]interface{},
) error {
	valueType, err := r.config.matrix.GetCriterionValueType(criterion.Name)
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
	var expr string
	switch valueType {
	case valueTypeList:
		expr, err = parseValuesToList(criterion.Value)
		if err != nil {
			return fmt.Errorf("failed to parse list value for criterion %s: %w", criterion.Name, err)
		}
	case valueTypeMap:
		expr, err = parseValuesToMap(criterion.Value)
		if err != nil {
			return fmt.Errorf("failed to parse map value for criterion %s: %w", criterion.Name, err)
		}
	default:
		return fmt.Errorf("unexpected valueType %q for criterion %s", valueType, criterion.Name)
	}

	newVar["expression"] = expr
	yamlObj["variables"] = append(varList, newVar)

	return nil
}

func (r *RuleConverter) outputPolicies(policies []Policy, filePath string) error {
	var buf bytes.Buffer

	for idx, policy := range policies {
		yamlBytes, err := yaml.Marshal(policy)
		if err != nil {
			return fmt.Errorf("failed to marshal policy at index %d: %w", idx, err)
		}

		buf.Write(yamlBytes)
		buf.WriteString("\n---\n")
	}

	if filePath == "" {
		_, err := os.Stdout.Write(buf.Bytes())
		return err
	}

	return os.WriteFile(filePath, buf.Bytes(), 0600)
}

func (r *RuleConverter) getNamespaceSelector(criterion *nvapis.RESTAdmRuleCriterion) (string, error) {
	if criterion == nil {
		return "", errors.New("criterion is nil")
	}

	userData, err := parseValuesToList(criterion.Value)
	if err != nil {
		return "", fmt.Errorf("failed to parse criterion values: %w", err)
	}

	switch criterion.Op {
	case nvdata.CriteriaOpContainsAny:
		return fmt.Sprintf("%s.exists(pattern, request.namespace.matches(pattern))", userData), nil
	case nvdata.CriteriaOpNotContainsAny:
		return fmt.Sprintf("!%s.exists(pattern, request.namespace.matches(pattern))", userData), nil
	default:
		return "", fmt.Errorf("unsupported operator: %s", criterion.Op)
	}
}

func (r *RuleConverter) generatePspComplianceMembers(
	_ *nvapis.RESTAdmRuleCriterion,
) ([]policiesv1.PolicyGroupMemberWithContext, error) {
	var members []policiesv1.PolicyGroupMemberWithContext

	yamlFiles := map[string]string{
		"templates/host_namespaces_psp.yaml": policyHostNamespacesPSP,
		fmt.Sprintf("templates/%s_%s.yaml", nvdata.CriteriaKeyRunAsPrivileged, normalizeOpName(nvdata.CriteriaOpEqual)):     policyPodPrivileged,
		fmt.Sprintf("templates/%s_%s.yaml", nvdata.CriteriaKeyRunAsRoot, normalizeOpName(nvdata.CriteriaOpEqual)):           policyUserGroupPSP,
		fmt.Sprintf("templates/%s_%s.yaml", nvdata.CriteriaKeyAllowPrivEscalation, normalizeOpName(nvdata.CriteriaOpEqual)): policyAllowPrivEscalation,
	}

	for yamlFile, module := range yamlFiles {
		yamlObj, err := readEmbeddedTemplate(yamlFile)
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

func buildRules() []admissionregistrationv1.RuleWithOperations {
	return []admissionregistrationv1.RuleWithOperations{
		{
			Operations: []admissionregistrationv1.OperationType{
				admissionregistrationv1.Create,
				admissionregistrationv1.Update,
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
