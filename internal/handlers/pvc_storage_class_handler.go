package handlers

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type PVCStorageClassHandler struct {
	BasePolicyHandler
}

const (
	RuleStorageClass         = "storageClassName"
	PolicyPVCStorageClassURI = "registry://ghcr.io/kubewarden/policies/persistentvolumeclaim-storageclass-policy:v1.1.0"
)

func NewPVCStorageClassHandler() *PVCStorageClassHandler {
	return &PVCStorageClassHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported: false,
			SupportedOps: map[string]bool{
				nvdata.CriteriaOpContainsAny:    true,
				nvdata.CriteriaOpNotContainsAny: true,
			},
			Name:               share.ExtractModuleName(PolicyPVCStorageClassURI),
			ApplicableResource: ResourcePVC,
			Module:             PolicyPVCStorageClassURI,
		},
	}
}

func (h *PVCStorageClassHandler) BuildPolicySettings(criteria []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	if len(criteria) != 1 {
		return nil, errors.New("only one criterion is allowed")
	}

	key := "allowedStorageClasses"
	if criteria[0].Op == nvdata.CriteriaOpContainsAny {
		key = "deniedStorageClasses"
	}

	settings := map[string][]string{
		key: strings.Split(criteria[0].Value, ","),
	}

	return json.Marshal(settings)
}
