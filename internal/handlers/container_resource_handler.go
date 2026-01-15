package handlers

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type ContainerResourceSettings struct {
	Memory *ResourceSettings `json:"memory,omitempty" yaml:"memory,omitempty"`
	CPU    *ResourceSettings `json:"cpu,omitempty"    yaml:"cpu,omitempty"`
}

type ResourceSettings struct {
	DefaultRequest *string `json:"defaultRequest,omitempty" yaml:"defaultRequest,omitempty"`
	DefaultLimit   *string `json:"defaultLimit,omitempty"   yaml:"defaultLimit,omitempty"`
	MaxLimit       *string `json:"maxLimit,omitempty"       yaml:"maxLimit,omitempty"`
	MaxRequest     *string `json:"maxRequest,omitempty"     yaml:"maxRequest,omitempty"`
	MinRequest     *string `json:"minRequest,omitempty"     yaml:"minRequest,omitempty"`
	MinLimit       *string `json:"minLimit,omitempty"       yaml:"minLimit,omitempty"`
}

type ContainerResourceHandler struct {
	BasePolicyHandler
}

const (
	PolicyContainerResourceURI = "registry://ghcr.io/kubewarden/policies/container-resources:v1.3.1"

	RuleResourceLimit = "resourceLimit"
)

func (rs *ResourceSettings) SetLimit(op, value string) {
	if op == nvdata.CriteriaOpBiggerThan {
		rs.MaxLimit = &value
	} else {
		rs.MinLimit = &value
	}
}

func (rs *ResourceSettings) SetRequest(op, value string) {
	if op == nvdata.CriteriaOpBiggerThan {
		rs.MaxRequest = &value
	} else {
		rs.MinRequest = &value
	}
}

func (rs *ResourceSettings) IsEmpty() bool {
	return rs == nil || (rs.DefaultRequest == nil &&
		rs.DefaultLimit == nil &&
		rs.MaxLimit == nil &&
		rs.MaxRequest == nil &&
		rs.MinRequest == nil &&
		rs.MinLimit == nil)
}

func NewContainerResourceHandler() *ContainerResourceHandler {
	return &ContainerResourceHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported: false,
			SupportedOps: map[string]bool{
				nvdata.CriteriaOpLessEqualThan: true,
				nvdata.CriteriaOpBiggerThan:    true,
				"":                             true,
			},
			Name:               share.ExtractModuleName(PolicyContainerResourceURI),
			Module:             PolicyContainerResourceURI,
			ApplicableResource: ResourceWorkload,
		},
	}
}

func (h *ContainerResourceHandler) BuildPolicySettings(criteria []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	if len(criteria) != 1 {
		return nil, errors.New("only one criterion is allowed")
	}

	// initialize the settings
	settings := ContainerResourceSettings{
		Memory: &ResourceSettings{},
		CPU:    &ResourceSettings{},
	}

	// implement the conversion logic
	criterion := criteria[0]
	for _, subCriterion := range criterion.SubCriteria {
		switch subCriterion.Name {
		case "cpuLimit":
			settings.CPU.SetLimit(subCriterion.Op, subCriterion.Value)
		case "cpuRequest":
			settings.CPU.SetRequest(subCriterion.Op, subCriterion.Value)
		case "memoryLimit":
			settings.Memory.SetLimit(subCriterion.Op, subCriterion.Value)
		case "memoryRequest":
			settings.Memory.SetRequest(subCriterion.Op, subCriterion.Value)
		default:
			return nil, fmt.Errorf("unsupported criterion: %s", subCriterion.Name)
		}
	}

	// Clean up empty resource settings
	if settings.Memory.IsEmpty() {
		settings.Memory = nil
	}
	if settings.CPU.IsEmpty() {
		settings.CPU = nil
	}

	return json.Marshal(settings)
}
