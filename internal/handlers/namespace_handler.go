package handlers

import (
	"errors"

	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type NamespaceHandler struct {
	BasePolicyHandler
}

const (
	RuleNamespace = "namespace"
)

func NewNamespaceHandler() *NamespaceHandler {
	return &NamespaceHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported: false,
			SupportedOps: map[string]bool{
				nvdata.CriteriaOpContainsAny:    true,
				nvdata.CriteriaOpNotContainsAny: true,
			},
			Name:               "namespace_selector",
			ApplicableResource: ResourceWorkload,
		},
	}
}

func (h *NamespaceHandler) BuildPolicySettings(_ []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	return nil, errors.New("building policy settings for namespace handler should never be done")
}
