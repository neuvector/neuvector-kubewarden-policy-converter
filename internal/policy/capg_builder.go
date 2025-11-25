package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/handlers"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type CAPGBuilder struct {
	BaseBuilder

	handlers map[string]share.PolicyHandler
}

func (b *CAPGBuilder) groupCriteriaByModule(
	rule *nvapis.RESTAdmissionRule,
) (map[string][]*nvapis.RESTAdmRuleCriterion, []string, error) {
	// Group criteria by their policy module
	applicableResources := []string{}
	moduleGroups := make(map[string][]*nvapis.RESTAdmRuleCriterion)
	for _, criterion := range rule.Criteria {
		// Group non-namespace criteria by their handler's module
		handler, exists := b.handlers[criterion.Name]
		if !exists {
			return nil, nil, fmt.Errorf("no handler found for criterion: %s", criterion.Name)
		}

		applicableResources = append(applicableResources, handler.GetApplicableResource())
		module := handler.GetModule()
		moduleGroups[module] = append(moduleGroups[module], criterion)
	}
	sort.Strings(applicableResources) // Ensure the resources are sorted in fixed order
	return moduleGroups, applicableResources, nil
}

func (b *CAPGBuilder) GeneratePolicy(rule *nvapis.RESTAdmissionRule, config share.ConversionConfig) (Policy, error) {
	var (
		policies            = policiesv1.PolicyGroupMembersWithContext{}
		conditions          []string
		matchConds          []admissionregistrationv1.MatchCondition
		moduleGroups        map[string][]*nvapis.RESTAdmRuleCriterion
		applicableResources []string
		settings            []byte
		err                 error
	)

	moduleGroups, applicableResources, err = b.groupCriteriaByModule(rule)
	if err != nil {
		return nil, fmt.Errorf("failed to group criteria by module: %w", err)
	}

	var namespaceSelector *metav1.LabelSelector
	for module, criteria := range moduleGroups {
		// Get handler from the first criterion (all criteria in this group use the same handler)
		handler := b.handlers[criteria[0].Name]
		policyName := share.ExtractModuleName(module)

		if criteria[0].Name == handlers.RuleNamespace {
			if len(criteria) > 1 {
				return nil, errors.New("rule skipped: contains multiple namespace selectors")
			}
			namespaceSelector = b.buildNamespaceSelector(criteria[0])
			continue
		}

		settings, err = handler.BuildPolicySettings(criteria)
		if err != nil {
			return nil, fmt.Errorf("failed to build policy settings: %w", err)
		}

		member := policiesv1.PolicyGroupMemberWithContext{
			PolicyGroupMember: policiesv1.PolicyGroupMember{
				Module: module,
				Settings: runtime.RawExtension{
					Raw: settings,
				},
			},
		}

		if ctxResources := handler.GetContextAwareResources(); len(ctxResources) > 0 {
			member.ContextAwareResources = ctxResources
		}

		policies[policyName] = member
		conditions = append(conditions, fmt.Sprintf("%s()", policyName))
	}

	// Ensure the conditions are sorted in fixed order
	sort.Strings(conditions)

	group := policiesv1.ClusterAdmissionPolicyGroup{
		TypeMeta: metav1.TypeMeta{
			Kind:       clusterAdmissionPolicyGroupKind,
			APIVersion: kwAPIVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: b.generatePolicyName(rule),
		},
		Spec: policiesv1.ClusterAdmissionPolicyGroupSpec{
			ClusterPolicyGroupSpec: policiesv1.ClusterPolicyGroupSpec{
				GroupSpec: policiesv1.GroupSpec{
					Message:         fmt.Sprintf("violate NeuVector rule (id=%d), comment %s", rule.ID, rule.Comment),
					Rules:           b.BuildRules(applicableResources),
					Mode:            policiesv1.PolicyMode(b.getRulelMode(rule, config)),
					PolicyServer:    config.PolicyServer,
					BackgroundAudit: config.BackgroundAudit,
					MatchConditions: matchConds,
					Expression:      strings.Join(conditions, " && "),
				},
				Policies: policies,
			},
			NamespaceSelector: namespaceSelector,
		},
	}

	return &group, nil
}
