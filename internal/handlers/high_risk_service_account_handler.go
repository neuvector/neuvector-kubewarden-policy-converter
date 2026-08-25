package handlers

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type HighRiskServiceAccountHandler struct {
	BasePolicyHandler
}

type highRiskSASettingsDetail map[string][]string

const (
	RuleHighRiskServiceAccount = "saBindRiskyRole"

	PolicyHighRiskServiceAccountURI = "registry://ghcr.io/kubewarden/policies/high-risk-service-account:v0.1.2"
)

func NewHighRiskServiceAccountHandler() *HighRiskServiceAccountHandler {
	return &HighRiskServiceAccountHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported: false,
			SupportedOps: map[string]bool{
				nvdata.CriteriaOpContainsTagAny: true,
			},
			Name:               share.ExtractModuleName(PolicyHighRiskServiceAccountURI),
			ApplicableResource: ResourceWorkload,
			Module:             PolicyHighRiskServiceAccountURI,
		},
	}
}

func (h *HighRiskServiceAccountHandler) BuildPolicySettings(criteria []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	if len(criteria) != 1 {
		return nil, errors.New("only one criterion is allowed")
	}

	var settings []highRiskSASettingsDetail

	riskTypes := strings.Split(criteria[0].Value, ",")
	for _, riskType := range riskTypes {
		switch riskType {
		case "risky_role_view_secret":
			settings = append(settings, highRiskSASettingsDetail{
				share.RBACFieldAPIGroups: []string{""},
				share.RBACFieldResources: []string{"secrets"},
				share.RBACFieldVerbs:     []string{"list", "get"},
			})
		case "risky_role_any_action_workload":
			settings = append(settings,
				highRiskSASettingsDetail{
					share.RBACFieldAPIGroups: []string{""},
					share.RBACFieldResources: []string{"pods", "pods/log"},
					share.RBACFieldVerbs:     []string{"*"},
				},
				highRiskSASettingsDetail{
					share.RBACFieldAPIGroups: []string{"apps"},
					share.RBACFieldResources: []string{"deployments", "statefulsets", "daemonsets", "replicasets"},
					share.RBACFieldVerbs:     []string{"*"},
				},
				highRiskSASettingsDetail{
					share.RBACFieldAPIGroups: []string{"batch"},
					share.RBACFieldResources: []string{"jobs", "cronjobs"},
					share.RBACFieldVerbs:     []string{"*"},
				},
				highRiskSASettingsDetail{
					share.RBACFieldAPIGroups: []string{"autoscaling"},
					share.RBACFieldResources: []string{"horizontalpodautoscalers"},
					share.RBACFieldVerbs:     []string{"*"},
				},
			)
		case "risky_role_any_action_rbac":
			settings = append(settings, highRiskSASettingsDetail{
				share.RBACFieldAPIGroups: []string{"rbac.authorization.k8s.io"},
				share.RBACFieldResources: []string{"roles", "rolebindings"},
				share.RBACFieldVerbs:     []string{"*"},
			})
		case "risky_role_create_pod":
			settings = append(settings, highRiskSASettingsDetail{
				share.RBACFieldAPIGroups: []string{""},
				share.RBACFieldResources: []string{"pods"},
				share.RBACFieldVerbs:     []string{"create"},
			})
		case "risky_role_exec_into_container":
			settings = append(settings, highRiskSASettingsDetail{
				share.RBACFieldAPIGroups: []string{""},
				share.RBACFieldResources: []string{"pods/exec"},
				share.RBACFieldVerbs:     []string{"create"},
			})
		}
	}

	return json.Marshal(map[string][]highRiskSASettingsDetail{"blockRules": settings})
}
