package handlers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

const (
	PolicyTrustedReposPolicyURI = "registry://ghcr.io/kubewarden/policies/trusted-repos:v2.0.1"

	RuleImageRegistry = "imageRegistry"
	RuleImage         = "image"
)

// TrustedReposHandler handles trusted repository policies.
type TrustedReposHandler struct {
	BasePolicyHandler
}

func NewTrustedReposHandler() *TrustedReposHandler {
	return &TrustedReposHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported: false,
			SupportedOps: map[string]bool{
				nvdata.CriteriaOpContainsAny:    true,
				nvdata.CriteriaOpNotContainsAny: true,
			},
			Name:               share.ExtractModuleName(PolicyTrustedReposPolicyURI),
			Module:             PolicyTrustedReposPolicyURI,
			ApplicableResource: ResourceWorkload,
		},
	}
}

// BuildPolicySettings builds settings from multiple criteria that map to the same module
/*
   Will reject the the following registries:
   registries:
     reject:
     - registry.my-corp.com

   Will reject the following images:
   images:
     reject:
     - quay.io/etcd/etcd:v3.4.12

   Will allow the the following registries, reject the rest:
   registries:
     allow:
     - registry.my-corp.com

   Will allow the following images, reject the rest:
   images:
     allow:
     - quay.io/etcd/etcd:v3.4.12
*/
func (h *TrustedReposHandler) BuildPolicySettings(criteria []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	settings := map[string]map[string][]string{}
	var operator string
	for _, criterion := range criteria {
		if criterion.Op == nvdata.CriteriaOpContainsAny {
			operator = "reject"
		} else {
			operator = "allow"
		}
		switch criterion.Name {
		case RuleImageRegistry:
			if settings["registries"] == nil {
				settings["registries"] = make(map[string][]string)
			}
			settings["registries"][operator] = strings.Split(criterion.Value, ",")
		case RuleImage:
			if settings["images"] == nil {
				settings["images"] = make(map[string][]string)
			}
			settings["images"][operator] = strings.Split(criterion.Value, ",")
		default:
			return nil, fmt.Errorf("unsupported criterion: %s", criterion.Name)
		}
	}

	settingsBytes, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	return settingsBytes, nil
}
