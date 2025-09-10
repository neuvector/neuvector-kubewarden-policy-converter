package policy

import (
	"fmt"

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
	// Use handler to process criterion
	criterion := rule.Criteria[0]
	handler, exists := b.handlers[criterion.Name]
	if !exists {
		return nil, fmt.Errorf("no handler found for criterion: %s", criterion.Name)
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
				MatchConditions: []admissionregistrationv1.MatchCondition{},
				Rules:           b.BuildRules([]string{handler.GetApplicableResource()}),
				Mode:            policiesv1.PolicyMode(b.getRuleModule(rule, config)),
				PolicyServer:    config.PolicyServer,
				BackgroundAudit: config.BackgroundAudit,
			},
		},
	}

	// Get module from handler
	policy.Spec.PolicySpec.Module = handler.GetModule()

	// Build policy settings using handler
	settings, err := handler.BuildPolicySettings(rule.Criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to build policy settings: %w", err)
	}

	policy.Spec.PolicySpec.Settings = runtime.RawExtension{
		Raw: settings,
	}

	return &policy, nil
}
