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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/customrule"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/handlers"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/metacriterion"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/policy"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	"sigs.k8s.io/yaml"
)

type RuleConverter struct {
	config         share.ConversionConfig
	policyFactory  *policy.Factory
	logger         *slog.Logger
	showSummary    bool
	handlers       map[string]share.PolicyHandler
	metaCriterions map[string]metacriterion.MetaCriterion
}

type ConversionResult struct {
	Policies  []Policy
	RegoCount int
	Summary   []summaryEntry
}

const (
	defaultColumnWidth = 50
	defaultNVRuleIDMax = 1000

	summaryEntryStatusOK      = "OK"
	summaryEntryStatusSkipped = "Skipped"
)

func NewRuleConverter(config share.ConversionConfig) *RuleConverter {
	rc := &RuleConverter{
		config:        config,
		policyFactory: policy.NewFactory(),
		showSummary:   config.ShowSummary,
		logger:        slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	rc.initHandlers()
	rc.initMetaCriterions()
	rc.policyFactory.SetHandlers(rc.handlers)

	return rc
}

func (r *RuleConverter) initHandlers() {
	r.handlers = map[string]share.PolicyHandler{
		handlers.RuleShareIPC:                  handlers.NewHostNamespaceHandler(),
		handlers.RuleShareNetwork:              handlers.NewHostNamespaceHandler(),
		handlers.RuleSharePID:                  handlers.NewHostNamespaceHandler(),
		handlers.RuleAllowPrivilegedEscalation: handlers.NewAllowPrivilegedEscalationHandler(),
		handlers.RuleRunAsRoot:                 handlers.NewContainerRunningAsUserHandler(),
		handlers.RuleRunAsPrivileged:           handlers.NewPodPrivilegedHandler(),
		handlers.RuleStorageClass:              handlers.NewPVCStorageClassHandler(),
		handlers.RuleEnvVars:                   handlers.NewEnvVarHandler(),
		handlers.RuleEnvVarSecret:              handlers.NewEnvVarSecretHandler(),
		handlers.RuleImage:                     handlers.NewTrustedReposHandler(),
		handlers.RuleImageRegistry:             handlers.NewTrustedReposHandler(),
		handlers.RuleNamespace:                 handlers.NewNamespaceHandler(),
		handlers.RuleHighRiskServiceAccount:    handlers.NewHighRiskServiceAccountHandler(),
		handlers.RuleLabels:                    handlers.NewLabelsPolicyHandler(),
		handlers.RuleAnnotations:               handlers.NewAnnotationsPolicyHandler(),
		handlers.RuleImageScanned: handlers.NewImageCVEHandler(
			r.config.VulReportNamespace,
			r.config.Platform,
		),
		handlers.RuleHighCVECount: handlers.NewImageCVEHandler(
			r.config.VulReportNamespace,
			r.config.Platform,
		),
		handlers.RuleMedCVECount: handlers.NewImageCVEHandler(
			r.config.VulReportNamespace,
			r.config.Platform,
		),
	}
}

func (r *RuleConverter) initMetaCriterions() {
	r.metaCriterions = map[string]metacriterion.MetaCriterion{
		metacriterion.RulePSPBestPractices: metacriterion.NewPSPBestPracticeMetaCriterion(),
	}
}

func (r *RuleConverter) Convert(ctx context.Context, ruleFile string) error {
	loader := NewRuleParser(ruleFile)
	admissionRules, err := loader.ParseRules()
	if err != nil {
		return fmt.Errorf("failed to parse NeuVector Admission rules: %w", err)
	}

	result := r.convertRules(ctx, admissionRules.Rules)

	// Write all generated policies to the output file, but only if there are one or more policies
	// Custom rules generate Rego files only, so policies may be empty
	if len(result.Policies) > 0 {
		if err = r.outputPolicies(result.Policies, r.config.OutputFile); err != nil {
			return fmt.Errorf("failed to write output YAML: %w", err)
		}
	}

	if r.showSummary {
		err = r.renderResultsTable(result.Summary)
		if err != nil {
			return fmt.Errorf("failed to render results table: %w", err)
		}
	}

	if result.RegoCount > 0 {
		r.logger.InfoContext(ctx, "rego policies generated",
			"count", result.RegoCount,
			"directory", "rego_policies/",
		)
	}

	if r.config.OutputFile != "-" && len(result.Policies) > 0 {
		r.logger.InfoContext(ctx, "Conversion done", "output_file", r.config.OutputFile)
	}

	return nil
}

// expandMetaCriterion processes and expands meta criteria in admission rules.
// In NeuVector, meta criteria are used to group related criteria into a single entity.
//
// This function modifies the nvRule object IN-PLACE by expanding any meta criterion
// definitions into their concrete counterparts.
func (r *RuleConverter) expandMetaCriterion(nvRule *nvapis.RESTAdmissionRule) error {
	var criteria []*nvapis.RESTAdmRuleCriterion

	for _, criterion := range nvRule.Criteria {
		if ruleToEquivalentCriteria, exists := r.metaCriterions[criterion.Name]; exists {
			if !ruleToEquivalentCriteria.GetSupportedOps()[criterion.Op] {
				return fmt.Errorf("%s: %s", share.MsgUnsupportedCriteriaOperator, criterion.Op)
			}
			criteria = append(criteria, ruleToEquivalentCriteria.Expand()...)
		} else {
			criteria = append(criteria, criterion)
		}
	}

	nvRule.Criteria = criteria
	return nil
}

func (r *RuleConverter) containsCustomRule(rule *nvapis.RESTAdmissionRule) bool {
	for _, criterion := range rule.Criteria {
		if customrule.IsCustomRule(criterion.Name) {
			return true
		}
	}
	return false
}

func (r *RuleConverter) convertRules(
	ctx context.Context,
	nvRules []*nvapis.RESTAdmissionRule,
) ConversionResult {
	var (
		convertedPolicy Policy
		policies        []Policy
		regoCount       int
		err             error
		summary         []summaryEntry
	)

	for _, rule := range nvRules {
		if err = r.expandMetaCriterion(rule); err != nil {
			summary = append(summary, summaryEntry{id: rule.ID, status: summaryEntryStatusSkipped, notes: err.Error()})
			continue
		}
		if r.containsCustomRule(rule) {
			err = customrule.BuildRegoPolicy(rule)
			if err != nil {
				summary = append(
					summary,
					summaryEntry{id: rule.ID, status: summaryEntryStatusSkipped, notes: err.Error()},
				)
				continue
			}
			summary = append(
				summary,
				summaryEntry{
					id:     rule.ID,
					status: summaryEntryStatusOK,
					notes:  "Rego policy generated (no policy YAML for custom rule)",
				},
			)
			regoCount++
			continue
		}
		convertedPolicy, err = r.convertRule(ctx, rule)
		if err != nil {
			summary = append(summary, summaryEntry{id: rule.ID, status: summaryEntryStatusSkipped, notes: err.Error()})
			continue
		}
		summary = append(
			summary,
			summaryEntry{id: rule.ID, status: summaryEntryStatusOK, notes: share.MsgRuleConvertedSuccessfully},
		)
		policies = append(policies, convertedPolicy)
	}

	return ConversionResult{
		Policies:  policies,
		RegoCount: regoCount,
		Summary:   summary,
	}
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
		criteriaName := criterion.Name
		// Custom rule handler does not have a fixed criteria ops, so we do not validate it
		if customrule.IsCustomRule(criterion.Name) {
			continue
		}

		handler, exists := r.handlers[criteriaName]
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

func (r *RuleConverter) convertRule(ctx context.Context, rule *nvapis.RESTAdmissionRule) (Policy, error) {
	err := r.validateRule(rule)
	if err != nil {
		return nil, err
	}

	policyObj, err := r.policyFactory.GeneratePolicy(rule, r.config)
	if err != nil {
		r.logger.InfoContext(ctx, "error when generating Kubewarden policy", "error", err)
		return nil, fmt.Errorf("%s: %w", share.MsgRuleGenerateKWPolicyError, err)
	}

	// Type assert to convert to our Policy interface
	var policy Policy
	switch p := policyObj.(type) {
	case *policiesv1.ClusterAdmissionPolicy:
		policy = p
	case *policiesv1.ClusterAdmissionPolicyGroup:
		policy = p
	default:
		return nil, errors.New("unexpected policy type")
	}

	return policy, nil
}

func (r *RuleConverter) renderResultsTable(summary []summaryEntry) error {
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
	for _, entry := range summary {
		data := []string{
			strconv.FormatUint(uint64(entry.id), 10),
			entry.status,
			entry.notes,
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

	if filePath == "-" {
		_, err := os.Stdout.Write(buf.Bytes())
		return err
	}

	return os.WriteFile(filePath, buf.Bytes(), 0600)
}
