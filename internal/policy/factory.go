package policy

import (
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

// Factory implements PolicyFactory with handler integration.
type Factory struct {
	handlers map[string]share.PolicyHandler
}

func NewFactory() *Factory {
	return &Factory{
		handlers: make(map[string]share.PolicyHandler),
	}
}

func (f *Factory) SetHandlers(handlers map[string]share.PolicyHandler) {
	f.handlers = handlers
}

func (f *Factory) CreateBuilder(rule *nvapis.RESTAdmissionRule) Builder {
	if f.requiresPolicyGroup(rule) {
		capgBuilder := &CAPGBuilder{}
		capgBuilder.handlers = f.handlers
		return capgBuilder
	}
	capBuilder := &CAPBuilder{}
	capBuilder.handlers = f.handlers
	return capBuilder
}

func (f *Factory) GeneratePolicy(rule *nvapis.RESTAdmissionRule, config share.ConversionConfig) (Policy, error) {
	builder := f.CreateBuilder(rule)
	return builder.GeneratePolicy(rule, config)
}

func (f *Factory) requiresPolicyGroup(rule *nvapis.RESTAdmissionRule) bool {
	count := 0
	for _, criterion := range rule.Criteria {
		if criterion.Name != nvdata.CriteriaKeyNamespace {
			count++
		}
	}
	return count > 1
}
