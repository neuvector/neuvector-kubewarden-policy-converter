package customrule

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	nvapis "github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/opa"
	nvshare "github.com/neuvector/neuvector/share"
)

const (
	RuleCustom        = "customPath"
	RegoDir           = "rego_policies"
	KubewardenPackage = "package kubernetes.admission"
)

func IsCustomRule(name string) bool {
	return name == RuleCustom || name == ""
}

func convertContainers(containers []string) uint8 {
	if len(containers) == 0 {
		return 0
	}
	var mask uint8
	for _, c := range containers {
		switch c {
		case nvshare.AdmCtrlRuleContainers:
			mask |= nvshare.AdmCtrlRuleContainersN
		case nvshare.AdmCtrlRuleInitContainers:
			mask |= nvshare.AdmCtrlRuleInitContainersN
		case nvshare.AdmCtrlRuleEphemeralContainers:
			mask |= nvshare.AdmCtrlRuleEphemeralContainersN
		}
	}

	return mask
}

func cfgTypeFromString(cfgType string) nvshare.TCfgType {
	switch cfgType {
	case "learned":
		return nvshare.Learned
	case "ground":
		return nvshare.GroundCfg
	case "federal":
		return nvshare.FederalCfg
	case "system_defined":
		return nvshare.SystemDefined
	default:
		return nvshare.UserCreated
	}
}

// convertToCLUSAdmissionRule converts RESTAdmissionRule to CLUSAdmissionRule.
func convertToCLUSAdmissionRule(
	rule *nvapis.RESTAdmissionRule,
) (*nvshare.CLUSAdmissionRule, error) {
	// Convert each RESTAdmRuleCriterion to CLUSAdmRuleCriterion.
	// Both types are identical by design; marshal/unmarshal is safer than manual field copying.
	clusCriteria := make([]*nvshare.CLUSAdmRuleCriterion, 0, len(rule.Criteria))
	for _, criterion := range rule.Criteria {
		jsonCriterion, err := json.Marshal(criterion)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal criterion: %w", err)
		}
		var clusCriterion nvshare.CLUSAdmRuleCriterion
		err = json.Unmarshal(jsonCriterion, &clusCriterion)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal criterion: %w", err)
		}
		clusCriteria = append(clusCriteria, &clusCriterion)
	}

	return &nvshare.CLUSAdmissionRule{
		ID:         rule.ID,
		Category:   rule.Category,
		Comment:    rule.Comment,
		Criteria:   clusCriteria,
		Disable:    rule.Disable,
		Critical:   rule.Critical,
		CfgType:    cfgTypeFromString(rule.CfgType),
		RuleType:   rule.RuleType,
		RuleMode:   rule.RuleMode,
		Containers: convertContainers(rule.Containers),
	}, nil
}

// BuildRegoPolicy generates a Kubewarden-compatible Rego policy from a NeuVector admission rule.
func BuildRegoPolicy(rule *nvapis.RESTAdmissionRule) error {
	clusRule, err := convertToCLUSAdmissionRule(rule)
	if err != nil {
		return fmt.Errorf("failed to convert rule to CLUSAdmissionRule: %w", err)
	}

	options := &opa.RegoConversionOptions{
		PackageName:            "kubernetes.admission",
		GenerateKubewardenMode: true,
	}

	regoCode, err := opa.GenerateRegoCode(clusRule, options)
	if err != nil {
		return fmt.Errorf("failed to generate rego code: %w", err)
	}

	if err = os.MkdirAll(RegoDir, 0750); err != nil {
		return fmt.Errorf("failed to create Rego directory: %w", err)
	}

	regoPolicyPath := filepath.Join(RegoDir, fmt.Sprintf("nv_rule_%d.rego", rule.ID))
	if err = os.WriteFile(regoPolicyPath, []byte(regoCode), 0600); err != nil {
		return fmt.Errorf("failed to write rego code: %w", err)
	}

	return nil
}
