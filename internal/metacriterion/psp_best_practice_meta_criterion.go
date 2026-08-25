package metacriterion

import (
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/handlers"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

const (
	RulePSPBestPractices = "pspCompliance"
)

type PSPBestPracticeMetaCriterion struct {
	SupportedOps map[string]bool
}

func NewPSPBestPracticeMetaCriterion() *PSPBestPracticeMetaCriterion {
	return &PSPBestPracticeMetaCriterion{
		SupportedOps: map[string]bool{
			nvdata.CriteriaOpEqual: true,
		},
	}
}

func (p *PSPBestPracticeMetaCriterion) GetSupportedOps() map[string]bool {
	return p.SupportedOps
}

func (p *PSPBestPracticeMetaCriterion) Expand() []*nvapis.RESTAdmRuleCriterion {
	return []*nvapis.RESTAdmRuleCriterion{
		{
			Name:  handlers.RuleShareIPC,
			Op:    nvdata.CriteriaOpEqual,
			Value: share.ValueTrue,
		},
		{
			Name:  handlers.RuleShareNetwork,
			Op:    nvdata.CriteriaOpEqual,
			Value: share.ValueTrue,
		},
		{
			Name:  handlers.RuleSharePID,
			Op:    nvdata.CriteriaOpEqual,
			Value: share.ValueTrue,
		},
		{
			Name:  handlers.RuleRunAsPrivileged,
			Op:    nvdata.CriteriaOpEqual,
			Value: share.ValueTrue,
		},
		{
			Name:  handlers.RuleRunAsRoot,
			Op:    nvdata.CriteriaOpEqual,
			Value: share.ValueTrue,
		},
		{
			Name:  handlers.RuleAllowPrivilegedEscalation,
			Op:    nvdata.CriteriaOpEqual,
			Value: share.ValueTrue,
		},
	}
}
