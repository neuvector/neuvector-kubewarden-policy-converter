package policy

import (
	"errors"
	"fmt"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/handlers"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	nvapis "github.com/neuvector/neuvector/controller/api"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type CAPBuilder struct {
	BaseBuilder

	handlers map[string]share.PolicyHandler
}

func (b *CAPBuilder) GeneratePolicy(rule *nvapis.RESTAdmissionRule, config share.ConversionConfig) (Policy, error) {
	var namespaceSelector *metav1.LabelSelector
	var policyHandler share.PolicyHandler
	var applicableResources []string
	var policyCriteria []*nvapis.RESTAdmRuleCriterion

	for _, criterion := range rule.Criteria {
		handler, exists := b.handlers[criterion.Name]
		if !exists {
			return nil, fmt.Errorf("no handler found for criterion: %s", criterion.Name)
		}
		if criterion.Name == handlers.RuleNamespace {
			if namespaceSelector != nil {
				return nil, errors.New("rule skipped: contains multiple namespace selectors")
			}
			namespaceSelector = b.buildNamespaceSelector(criterion)
		} else {
			policyHandler = handler
			policyCriteria = append(policyCriteria, criterion)
			applicableResources = append(applicableResources, handler.GetApplicableResource())
		}
	}

	// Ignore rules that contain only namespace criteria as they don't represent meaningful policies
	if policyHandler == nil {
		return nil, errors.New(
			"rule skipped: contains only namespace selector without enforceable policy conditions for criteria",
		)
	}

	// Build policy settings using handler
	settings, err := policyHandler.BuildPolicySettings(policyCriteria)
	if err != nil {
		return nil, fmt.Errorf("failed to build policy settings: %w", err)
	}

	policy := policiesv1.ClusterAdmissionPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       clusterAdmissionPolicyKind,
			APIVersion: kwAPIVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: b.generatePolicyName(rule),
		},
		Spec: policiesv1.ClusterAdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				Rules:           b.BuildRules(applicableResources),
				MatchConditions: []admissionregistrationv1.MatchCondition{},
				Mode:            policiesv1.PolicyMode(b.getRulelMode(rule, config)),
				Module:          policyHandler.GetModule(),
				PolicyServer:    config.PolicyServer,
				BackgroundAudit: config.BackgroundAudit,
				Settings: runtime.RawExtension{
					Raw: settings,
				},
			},
			NamespaceSelector: namespaceSelector,
		},
	}

	return &policy, nil
}
