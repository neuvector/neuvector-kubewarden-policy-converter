package handlers

import (
	"errors"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
)

const (
	PolicySettingCriteria       = "criteria"
	PolicySettingValues         = "values"
	PolicySettingCELValidations = "validations"
	PolicySettingCELExpression  = "expression"
	PolicySettingCELMessage     = "message"
)

// BasePolicyHandler provides base implementation for PolicyHandler interface.
type BasePolicyHandler struct {
	Name         string
	Module       string
	Unsupported  bool
	SupportedOps map[string]bool
}

type CELValidation struct {
	Expression string `json:"expression"`
	Message    string `json:"message"`
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
