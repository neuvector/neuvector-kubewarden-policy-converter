package handlers

import (
	"errors"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
)

const (
	ResourcePVC      = "pvc"
	ResourceWorkload = "workload"
)

// BasePolicyHandler provides base implementation for PolicyHandler interface.
type BasePolicyHandler struct {
	Name                  string
	Module                string
	Unsupported           bool
	ApplicableResource    string
	SupportedOps          map[string]bool
	ContextAwareResources []policiesv1.ContextAwareResource
}

func (h *BasePolicyHandler) Validate(rule *nvapis.RESTAdmRuleCriterion) error {
	if h.Unsupported {
		return errors.New(share.MsgUnsupportedRuleCriteria)
	}

	// criteria is supported, now check it's operator
	if !h.SupportedOps[rule.Op] {
		return errors.New(share.MsgUnsupportedCriteriaOperator)
	}

	return nil
}

func (h *BasePolicyHandler) IsUnsupported() bool {
	return h.Unsupported
}

func (h *BasePolicyHandler) GetSupportedOps() map[string]bool {
	return h.SupportedOps
}

func (h *BasePolicyHandler) GetModule() string {
	return h.Module
}

func (h *BasePolicyHandler) GetApplicableResource() string {
	return h.ApplicableResource
}

func (h *BasePolicyHandler) GetContextAwareResources() []policiesv1.ContextAwareResource {
	return h.ContextAwareResources
}
