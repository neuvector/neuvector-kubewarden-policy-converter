package policy

import (
	"errors"
	"testing"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/handlers"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
)

func TestFactory_CreateBuilder(t *testing.T) {
	tests := []struct {
		name         string
		rule         *nvapis.RESTAdmissionRule
		expectedType string
	}{
		{
			name: "single non-namespace criterion returns CAPBuilder",
			rule: &nvapis.RESTAdmissionRule{
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:  handlers.RuleShareIPC,
						Op:    nvdata.CriteriaOpEqual,
						Value: "true",
					},
				},
			},
			expectedType: "*policy.CAPBuilder",
		},
		{
			name: "multiple non-namespace criteria returns CAPGBuilder",
			rule: &nvapis.RESTAdmissionRule{
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:  handlers.RuleShareIPC,
						Op:    nvdata.CriteriaOpEqual,
						Value: "true",
					},
					{
						Name:  handlers.RuleShareNetwork,
						Op:    nvdata.CriteriaOpEqual,
						Value: "false",
					},
				},
			},
			expectedType: "*policy.CAPGBuilder",
		},
		{
			name: "namespace criterion only returns CAPBuilder",
			rule: &nvapis.RESTAdmissionRule{
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:  nvdata.CriteriaKeyNamespace,
						Op:    nvdata.CriteriaOpEqual,
						Value: "kube-system",
					},
				},
			},
			expectedType: "*policy.CAPBuilder",
		},
		{
			name: "namespace + one other criterion returns CAPBuilder",
			rule: &nvapis.RESTAdmissionRule{
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:  nvdata.CriteriaKeyNamespace,
						Op:    nvdata.CriteriaOpEqual,
						Value: "kube-system",
					},
					{
						Name:  handlers.RuleShareIPC,
						Op:    nvdata.CriteriaOpEqual,
						Value: "true",
					},
				},
			},
			expectedType: "*policy.CAPBuilder",
		},
		{
			name: "namespace + two other criteria returns CAPGBuilder",
			rule: &nvapis.RESTAdmissionRule{
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:  nvdata.CriteriaKeyNamespace,
						Op:    nvdata.CriteriaOpEqual,
						Value: "kube-system",
					},
					{
						Name:  handlers.RuleShareIPC,
						Op:    nvdata.CriteriaOpEqual,
						Value: "true",
					},
					{
						Name:  handlers.RuleShareNetwork,
						Op:    nvdata.CriteriaOpEqual,
						Value: "false",
					},
				},
			},
			expectedType: "*policy.CAPGBuilder",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := NewFactory()
			builder := factory.CreateBuilder(tt.rule)

			builderType := getTypeName(builder)
			require.Equal(t, tt.expectedType, builderType)
		})
	}
}

func TestFactory_RequiresPolicyGroup(t *testing.T) {
	tests := []struct {
		name     string
		rule     *nvapis.RESTAdmissionRule
		expected bool
	}{
		{
			name: "no criteria",
			rule: &nvapis.RESTAdmissionRule{
				Criteria: []*nvapis.RESTAdmRuleCriterion{},
			},
			expected: false,
		},
		{
			name: "only namespace criterion",
			rule: &nvapis.RESTAdmissionRule{
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: nvdata.CriteriaKeyNamespace},
				},
			},
			expected: false,
		},
		{
			name: "one non-namespace criterion",
			rule: &nvapis.RESTAdmissionRule{
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: handlers.RuleShareIPC},
				},
			},
			expected: false,
		},
		{
			name: "two non-namespace criteria",
			rule: &nvapis.RESTAdmissionRule{
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: handlers.RuleShareIPC},
					{Name: handlers.RuleShareNetwork},
				},
			},
			expected: true,
		},
		{
			name: "namespace + one non-namespace criterion",
			rule: &nvapis.RESTAdmissionRule{
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: nvdata.CriteriaKeyNamespace},
					{Name: handlers.RuleShareIPC},
				},
			},
			expected: false,
		},
		{
			name: "namespace + two non-namespace criteria",
			rule: &nvapis.RESTAdmissionRule{
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{Name: nvdata.CriteriaKeyNamespace},
					{Name: handlers.RuleShareIPC},
					{Name: handlers.RuleShareNetwork},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := NewFactory()
			result := factory.requiresPolicyGroup(tt.rule)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestFactory_SetHandlers(t *testing.T) {
	factory := NewFactory()

	// Initially empty
	require.Empty(t, factory.handlers)

	handlers := map[string]share.PolicyHandler{
		"test1": handlers.NewHostNamespaceHandler(),
		"test2": handlers.NewHostNamespaceHandler(),
	}

	factory.SetHandlers(handlers)

	require.Len(t, factory.handlers, 2)
	require.Equal(t, handlers, factory.handlers)
}

func TestFactory_GeneratePolicy(t *testing.T) {
	tests := []struct {
		name          string
		rule          *nvapis.RESTAdmissionRule
		config        share.ConversionConfig
		handlers      map[string]share.PolicyHandler
		expectedError error
	}{
		{
			name: "successful generation with CAPBuilder",
			rule: &nvapis.RESTAdmissionRule{
				ID: 1234,
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:  handlers.RuleShareIPC,
						Op:    nvdata.CriteriaOpEqual,
						Value: "true",
					},
				},
			},
			config: share.ConversionConfig{
				Mode: "monitor",
			},
			handlers: map[string]share.PolicyHandler{
				handlers.RuleShareIPC: handlers.NewHostNamespaceHandler(),
			},
		},
		{
			name: "successful generation with CAPGBuilder",
			rule: &nvapis.RESTAdmissionRule{
				ID: 1234,
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:  handlers.RuleShareIPC,
						Op:    nvdata.CriteriaOpEqual,
						Value: "true",
					},
					{
						Name:  handlers.RuleShareNetwork,
						Op:    nvdata.CriteriaOpEqual,
						Value: "false",
					},
				},
			},
			config: share.ConversionConfig{
				Mode: "protect",
			},
			handlers: map[string]share.PolicyHandler{
				handlers.RuleShareIPC:     handlers.NewHostNamespaceHandler(),
				handlers.RuleShareNetwork: handlers.NewHostNamespaceHandler(),
			},
		},
		{
			name: "error from builder",
			rule: &nvapis.RESTAdmissionRule{
				ID: 1234,
				Criteria: []*nvapis.RESTAdmRuleCriterion{
					{
						Name:  "unknownCriterion",
						Op:    nvdata.CriteriaOpEqual,
						Value: "true",
					},
				},
			},
			config: share.ConversionConfig{
				Mode: "monitor",
			},
			handlers:      map[string]share.PolicyHandler{},
			expectedError: errors.New("no handler found for criterion: unknownCriterion"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := NewFactory()
			factory.SetHandlers(tt.handlers)

			policy, err := factory.GeneratePolicy(tt.rule, tt.config)
			require.Equal(t, tt.expectedError, err)

			if tt.expectedError != nil {
				require.Nil(t, policy)
			} else {
				require.NotNil(t, policy)
			}
		})
	}
}

func getTypeName(v interface{}) string {
	switch v.(type) {
	case *CAPBuilder:
		return "*policy.CAPBuilder"
	case *CAPGBuilder:
		return "*policy.CAPGBuilder"
	default:
		return "unknown"
	}
}
