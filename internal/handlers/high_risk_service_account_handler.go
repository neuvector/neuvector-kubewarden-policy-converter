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
				nvdata.CriteriaOpContainsAny: true,
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
				"apiGroups": []string{""},
				"resources": []string{"secrets"},
				"verbs":     []string{"list", "get"},
			})
		case "risky_role_any_action_workload":
			settings = append(settings,
				highRiskSASettingsDetail{
					"apiGroups": []string{""},
					"resources": []string{"pods", "pods/log"},
					"verbs":     []string{"*"},
				},
				highRiskSASettingsDetail{
					"apiGroups": []string{"apps"},
					"resources": []string{"deployments", "statefulsets", "daemonsets", "replicasets"},
					"verbs":     []string{"*"},
				},
				highRiskSASettingsDetail{
					"apiGroups": []string{"batch"},
					"resources": []string{"jobs", "cronjobs"},
					"verbs":     []string{"*"},
				},
				highRiskSASettingsDetail{
					"apiGroups": []string{"autoscaling"},
					"resources": []string{"horizontalpodautoscalers"},
					"verbs":     []string{"*"},
				},
			)
		case "risky_role_any_action_rbac":
			settings = append(settings, highRiskSASettingsDetail{
				"apiGroups": []string{"rbac.authorization.k8s.io"},
				"resources": []string{"roles", "rolebindings"},
				"verbs":     []string{"*"},
			})
		case "risky_role_create_pod":
			settings = append(settings, highRiskSASettingsDetail{
				"apiGroups": []string{""},
				"resources": []string{"pods"},
				"verbs":     []string{"create"},
			})
		case "risky_role_exec_into_container":
			settings = append(settings, highRiskSASettingsDetail{
				"apiGroups": []string{""},
				"resources": []string{"pods/exec"},
				"verbs":     []string{"create"},
			})
		}
	}

	return json.Marshal(map[string][]highRiskSASettingsDetail{"blockRules": settings})
}
