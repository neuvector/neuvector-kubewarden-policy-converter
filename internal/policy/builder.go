package policy

import (
	"fmt"
	"strings"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/handlers"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"

	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	kwAPIVersion                    = "policies.kubewarden.io/v1"
	clusterAdmissionPolicyKind      = "ClusterAdmissionPolicy"
	clusterAdmissionPolicyGroupKind = "ClusterAdmissionPolicyGroup"
	defaultMode                     = "protect"
)

type Policy interface{} // *policiesv1.ClusterAdmissionPolicy | *policiesv1.ClusterAdmissionPolicyGroup

type Builder interface {
	BuildRules(resources []string) []admissionregistrationv1.RuleWithOperations

	// It will be used to generate a single policy or a policy group.
	GeneratePolicy(rule *nvapis.RESTAdmissionRule, config share.ConversionConfig) (Policy, error)
}

type BaseBuilder struct{}

// BuildRules determines which Kubernetes resources to apply admission rules to.
func (b *BaseBuilder) BuildRules(resources []string) []admissionregistrationv1.RuleWithOperations {
	rules := []admissionregistrationv1.RuleWithOperations{}
	resourcesMap := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		// Avoid duplicate resources
		if _, ok := resourcesMap[resource]; ok {
			continue
		}
		resourcesMap[resource] = struct{}{}
		switch resource {
		case handlers.ResourcePVC:
			rules = append(rules, b.BuildPVCRules()...)
		case handlers.ResourceWorkload:
			rules = append(rules, b.BuildWorkloadRules()...)
		}
	}

	return rules
}

func (b *BaseBuilder) BuildPVCRules() []admissionregistrationv1.RuleWithOperations {
	return []admissionregistrationv1.RuleWithOperations{
		{
			Operations: []admissionregistrationv1.OperationType{
				admissionregistrationv1.Create,
			},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"persistentvolumeclaims"},
			},
		},
	}
}

func (b *BaseBuilder) BuildWorkloadRules() []admissionregistrationv1.RuleWithOperations {
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

// generatePolicyName generates a unique policy name based on the rule ID.
// Helps user to identify the nv rule is converted to which policy.
func (b *BaseBuilder) generatePolicyName(rule *nvapis.RESTAdmissionRule) string {
	return fmt.Sprintf("neuvector-rule-%d-conversion", rule.ID)
}

// getRulelMode determines the effective admission rule mode based on priority:
// CLI mode > File-defined mode > Default mode.
func (b *BaseBuilder) getRulelMode(rule *nvapis.RESTAdmissionRule, config share.ConversionConfig) string {
	if config.Mode != "" {
		return config.Mode
	}

	if rule.RuleMode != "" {
		return rule.RuleMode
	}
	return defaultMode
}

func (b *BaseBuilder) buildNamespaceSelector(criterion *nvapis.RESTAdmRuleCriterion) *metav1.LabelSelector {
	operator := metav1.LabelSelectorOpIn

	if criterion.Op == nvdata.CriteriaOpContainsAny {
		operator = metav1.LabelSelectorOpNotIn
	}

	return &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "metadata.namespace",
				Operator: operator,
				Values:   strings.Split(criterion.Value, ","),
			},
		},
	}
}
