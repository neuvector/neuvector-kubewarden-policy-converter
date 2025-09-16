package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type NamespacePolicyHandler struct {
	BasePolicyHandler
}

const (
	PolicyCELURI = "registry://ghcr.io/kubewarden/policies/cel-policy:v1.3.4"

	RuleNamespace = "namespace"
)

func NewNamespacePolicyHandler() *NamespacePolicyHandler {
	return &NamespacePolicyHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported: false,
			SupportedOps: map[string]bool{
				nvdata.CriteriaOpContainsAny:    true,
				nvdata.CriteriaOpNotContainsAny: true,
			},
			Name:               share.ExtractModuleName(PolicyCELURI),
			Module:             PolicyCELURI,
			ApplicableResource: ResourceWorkload,
		},
	}
}

func (h *NamespacePolicyHandler) BuildPolicySettings(criteria []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	if len(criteria) != 1 {
		return nil, errors.New("only one criterion is allowed")
	}

	settings := make(map[string][]CELValidation)
	criterion := criteria[0]

	// Convert a comma-separated string "foo, bar" into a slice of strings ["foo", "bar"]
	namespaces := strings.Split(criterion.Value, ",")

	quotedNamespaces := make([]string, len(namespaces))
	for i, v := range namespaces {
		quotedNamespaces[i] = fmt.Sprintf("\"%s\"", strings.TrimSpace(v))
	}
	namespacesList := strings.Join(quotedNamespaces, ", ")

	// Add \n in the end of the expression and message to make it easier to read in the policy.yaml file.
	var message, expression string
	if criterion.Op == nvdata.CriteriaOpContainsAny {
		message = fmt.Sprintf("Namespace must not be one of: %s.\n", namespacesList)
		expression = fmt.Sprintf(
			"has(object.metadata.namespace) && !(object.metadata.namespace in [%s])\n",
			namespacesList,
		)
	} else {
		message = fmt.Sprintf("Namespace must be one of: %s.\n", namespacesList)
		expression = fmt.Sprintf("has(object.metadata.namespace) && (object.metadata.namespace in [%s])\n", namespacesList)
	}

	settings[PolicySettingCELValidations] = []CELValidation{
		{
			Expression: expression,
			Message:    message,
		},
	}

	return json.Marshal(settings)
}
