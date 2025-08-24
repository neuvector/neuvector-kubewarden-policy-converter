package convert

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	nvapis "github.com/neuvector/neuvector/controller/api"
	nvResource "github.com/neuvector/neuvector/controller/resource"

	"go.yaml.in/yaml/v4"
)

const (
	DefaultRuleBaseID = 1000
	defaultRuleMode   = "protect"
)

type RuleParser struct {
	filePath string
	nextID   uint32
}

func NewRuleParser(filePath string) *RuleParser {
	return &RuleParser{
		filePath: filePath,
		nextID:   DefaultRuleBaseID,
	}
}

type K8sAdmissionRule struct {
	Spec nvResource.NvSecurityAdmCtrlRules `json:"spec" yaml:"spec"`
}

func (p *RuleParser) ParseRules() (*nvapis.RESTAdmissionRulesData, error) {
	file, err := os.Open(p.filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %q: %w", p.filePath, err)
	}
	defer file.Close()

	fileData, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file data: %w", err)
	}

	if p.isYAMLFile() {
		return p.parseYAMLRules(fileData)
	}
	return p.parseJSONRules(fileData)
}

func (p *RuleParser) isYAMLFile() bool {
	return strings.HasSuffix(p.filePath, ".yaml") || strings.HasSuffix(p.filePath, ".yml")
}

func (p *RuleParser) parseJSONRules(data []byte) (*nvapis.RESTAdmissionRulesData, error) {
	var restRules nvapis.RESTAdmissionRulesData
	if err := json.Unmarshal(data, &restRules); err != nil {
		return nil, fmt.Errorf("failed to decode JSON rules: %w", err)
	}
	return &restRules, nil
}

func (p *RuleParser) parseYAMLRules(data []byte) (*nvapis.RESTAdmissionRulesData, error) {
	var k8sRules K8sAdmissionRule

	if err := yaml.Unmarshal(data, &k8sRules); err != nil {
		return nil, fmt.Errorf("failed to decode YAML rules: %w", err)
	}

	return p.convertToRESTFormat(k8sRules.Spec)
}

/*
getRuleID determines and returns the ID for a rule.

For NeuVector versions prior to 5.4.7 (<= 5.4.6), rule IDs were not retained during export,
so the converter automatically generates a new ID.

From version 5.4.7 onwards, rule IDs are preserved.
*/
func (p *RuleParser) getRuleID(conversionIDRef *uint32) uint32 {
	if conversionIDRef != nil {
		return *conversionIDRef
	}
	currentID := p.nextID
	p.nextID++
	return currentID
}

func (p *RuleParser) convertNativeRuleToREST(
	nativeRule *nvResource.NvSecurityAdmCtrlRule,
) (*nvapis.RESTAdmissionRule, error) {
	if nativeRule == nil {
		return nil, errors.New("native rule cannot be nil")
	}

	restRule := &nvapis.RESTAdmissionRule{
		ID:         p.getRuleID(nativeRule.ConversionIdRef),
		Criteria:   nativeRule.Criteria,
		RuleType:   nvapis.ValidatingDenyRuleType,
		RuleMode:   defaultRuleMode,
		Critical:   false,
		Disable:    false,
		Comment:    "",
		Containers: nativeRule.Containers,
	}

	if nativeRule.Action != nil {
		restRule.RuleType = *nativeRule.Action
	}

	if nativeRule.RuleMode != nil {
		restRule.RuleMode = *nativeRule.RuleMode
	}

	if nativeRule.Comment != nil {
		restRule.Comment = *nativeRule.Comment
	}

	if nativeRule.Disabled != nil {
		restRule.Disable = *nativeRule.Disabled
	}

	return restRule, nil
}

func (p *RuleParser) convertToRESTFormat(
	nativeRules nvResource.NvSecurityAdmCtrlRules,
) (*nvapis.RESTAdmissionRulesData, error) {
	restData := &nvapis.RESTAdmissionRulesData{
		Rules: make([]*nvapis.RESTAdmissionRule, 0, len(nativeRules.Rules)),
	}

	for i, nativeRule := range nativeRules.Rules {
		restRule, err := p.convertNativeRuleToREST(nativeRule)
		if err != nil {
			return nil, fmt.Errorf("failed to convert rule at index %d: %w", i, err)
		}
		restData.Rules = append(restData.Rules, restRule)
	}

	return restData, nil
}
