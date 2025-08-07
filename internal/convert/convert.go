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
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/handlers"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/policy"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	"sigs.k8s.io/yaml"
)

type RuleConverter struct {
	config        share.ConversionConfig
	handlers      map[string]share.PolicyHandler
	supportMatrix map[string]share.PolicyHandler
	policyFactory *policy.Factory
}

const (
	defaultColumnWidth = 50
	defaultNVRuleIDMax = 1000
)

func NewRuleConverter(config share.ConversionConfig) *RuleConverter {
	rc := &RuleConverter{
		config:        config,
		policyFactory: policy.NewFactory(),
	}

	rc.initHandlers()
	rc.initSupportMatrix()
	rc.policyFactory.SetHandlers(rc.handlers)

	return rc
}

func (r *RuleConverter) initHandlers() {
	r.handlers = map[string]share.PolicyHandler{
		handlers.ShareIPC:     handlers.NewHostNamespaceHandler(),
		handlers.ShareNetwork: handlers.NewHostNamespaceHandler(),
		handlers.SharePID:     handlers.NewHostNamespaceHandler(),
	}
}

func (r *RuleConverter) initSupportMatrix() {
	r.supportMatrix = map[string]share.PolicyHandler{
		MatrixKeyShareIPC:     handlers.NewHostNamespaceHandler(),
		MatrixKeyShareNetwork: handlers.NewHostNamespaceHandler(),
		MatrixKeySharePID:     handlers.NewHostNamespaceHandler(),
	}
}

func (r *RuleConverter) Convert(input io.Reader) error {
	admissionRules, err := parseAdmissionRules(input)
	if err != nil {
		return fmt.Errorf("failed to parse NeuVector Admission rules: %w", err)
	}

	results, policies := r.convertRules(admissionRules.Rules)

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

func (r *RuleConverter) convertRules(nvRules []*nvapis.RESTAdmissionRule) ([]ruleParsingResult, []Policy) {
	var (
		results  []ruleParsingResult
		policies []Policy
	)

	for _, rule := range nvRules {
		result := r.convertRule(rule)
		results = append(results, result)

		if result.policy != nil {
			policies = append(policies, result.policy)
		}
	}
	return results, policies
}

func (r *RuleConverter) validateRule(rule *nvapis.RESTAdmissionRule) error {
	if rule.ID < defaultNVRuleIDMax {
		return errors.New(share.MsgNeuVectorRuleOnly)
	}

	if rule.RuleType != nvapis.ValidatingDenyRuleType {
		return fmt.Errorf("%s got %s", share.MsgOnlyDenyRuleSupported, rule.RuleType)
	}

	if rule.Disable {
		return fmt.Errorf("%s, got %t", share.MsgRuleDisabled, rule.Disable)
	}

	for _, criterion := range rule.Criteria {
		handler, exists := r.handlers[criterion.Name]
		if !exists {
			return fmt.Errorf("%s: %s", share.MsgUnsupportedRuleCriteria, criterion.Name)
		}

		if handler.IsUnsupported() {
			return fmt.Errorf("%s: %s", share.MsgUnsupportedRuleCriteria, criterion.Name)
		}

		if !handler.GetSupportedOps()[criterion.Op] {
			return fmt.Errorf("%s: %s", share.MsgUnsupportedCriteriaOperator, criterion.Op)
		}
	}

	return nil
}

func (r *RuleConverter) convertRule(rule *nvapis.RESTAdmissionRule) ruleParsingResult {
	err := r.validateRule(rule)
	if err != nil {
		return ruleParsingResult{id: rule.ID, pass: false, notes: err.Error()}
	}

	policyObj, err := r.policyFactory.GeneratePolicy(rule, r.config)
	if err != nil {
		note := fmt.Sprintf("%s: %v", share.MsgRuleGenerateKWPolicyError, err)
		return ruleParsingResult{id: rule.ID, pass: false, notes: note}
	}

	// Type assert to convert to our Policy interface
	var policy Policy
	switch p := policyObj.(type) {
	case *policiesv1.ClusterAdmissionPolicy:
		policy = p
	case *policiesv1.ClusterAdmissionPolicyGroup:
		policy = p
	default:
		return ruleParsingResult{id: rule.ID, pass: false, notes: "unexpected policy type"}
	}

	return ruleParsingResult{
		id:     rule.ID,
		pass:   true,
		notes:  share.MsgRuleConvertedSuccessfully,
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
		status := "OK"
		if !result.pass {
			status = "Skipped"
		}
		data := []string{
			strconv.FormatUint(uint64(result.id), 10),
			status,
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

func (r *RuleConverter) outputPolicies(policies []Policy, filePath string) error {
	var buf bytes.Buffer

	for idx, policy := range policies {
		yamlBytes, err := yaml.Marshal(policy)
		if err != nil {
			return fmt.Errorf("failed to marshal policy at index %d: %w", idx, err)
		}

		buf.Write(yamlBytes)
		if idx < len(policies)-1 {
			buf.WriteString("\n---\n")
		}
	}

	if filePath == "" {
		_, err := os.Stdout.Write(buf.Bytes())
		return err
	}

	return os.WriteFile(filePath, buf.Bytes(), 0600)
}

func (r *RuleConverter) ShowRules() error {
	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithConfig(tablewriter.Config{
			Row: tw.CellConfig{
				Formatting:   tw.CellFormatting{AutoWrap: tw.WrapNormal},
				Alignment:    tw.CellAlignment{Global: tw.AlignLeft},
				ColMaxWidths: tw.CellWidth{Global: defaultColumnWidth},
			},
		}),
	)
	table.Header([]string{"Criterion Name", "Supported", "Kubewarden Module"})

	for criterionName, handler := range r.supportMatrix {
		supportStatus := "Yes"
		if handler == nil || handler.IsUnsupported() {
			supportStatus = "No"
		}
		module := ""
		if handler != nil {
			module = handler.GetModule()
		}
		err := table.Append([]string{criterionName, supportStatus, module})
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
