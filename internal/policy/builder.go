package policy

import (
	"fmt"
	"strings"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

const (
	kwAPIVersion                    = "policies.kubewarden.io/v1"
	clusterAdmissionPolicyKind      = "ClusterAdmissionPolicy"
	clusterAdmissionPolicyGroupKind = "ClusterAdmissionPolicyGroup"
)

type Policy interface{} // *policiesv1.ClusterAdmissionPolicy | *policiesv1.ClusterAdmissionPolicyGroup

type Builder interface {
	BuildRules() []admissionregistrationv1.RuleWithOperations

	// It will be used to generate a single policy or a policy group.
	GeneratePolicy(rule *nvapis.RESTAdmissionRule, config share.ConversionConfig) (Policy, error)
}

type BaseBuilder struct{}

func (b *BaseBuilder) BuildRules() []admissionregistrationv1.RuleWithOperations {
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

// If user has the comment in the rule, use it as the policy name.
// Otherwise, use the rule id as the policy name.
// The policy name should be unique.
func (b *BaseBuilder) generatePolicyName(rule *nvapis.RESTAdmissionRule) string {
	if rule.Comment != "" {
		return strings.ReplaceAll(strings.ToLower(rule.Comment), " ", "-")
	}
	return fmt.Sprintf("neuvector-rule-%d-conversion", rule.ID)
}

func (b *BaseBuilder) getRuleModule(rule *nvapis.RESTAdmissionRule, config share.ConversionConfig) string {
	if rule.RuleMode != "" {
		return rule.RuleMode
	}
	return config.Mode
}
