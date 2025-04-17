/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package convert

import (
	"fmt"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

// Kubewarden policy modules
const (
	policyCEL                 = "registry://ghcr.io/kubewarden/policies/cel-policy:latest"
	policyHostNamespacesPSP   = "registry://ghcr.io/kubewarden/policies/host-namespaces-psp:v0.1.7"
	policyAllowPrivEscalation = "registry://ghcr.io/kubewarden/policies/allow-privilege-escalation-psp:v0.2.6"
	policyPodPrivileged       = "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.3.3"
	policyUserGroupPSP        = "registry://ghcr.io/kubewarden/policies/user-group-psp:v0.6.3"
	policyTrustedRepos        = "registry://ghcr.io/kubewarden/policies/trusted-repos:v0.2.0"
	policyEnvSecretScanner    = "registry://ghcr.io/kubewarden/policies/env-variable-secrets-scanner:v0.1.8" // #nosec G101
)

const (
	valueTypeNone = "none"
	valueTypeList = "list"
	valueTypeMap  = "map"

	mappingType1to1    = "1-1"
	mappingType1toMany = "1-many"
)

// GenerateMembersFuncType returns members for policy group mapping.
type GenerateMembersFuncType func(criterion *nvapis.RESTAdmRuleCriterion) ([]policiesv1.PolicyGroupMemberWithContext, error)

// PolicySettingFunc injects policy-specific settings into a YAML object.
type PolicySettingFunc func(criterion *nvapis.RESTAdmRuleCriterion, yamlObj map[string]interface{}) error

// criterionMapping defines how each NeuVector criterion maps to Kubewarden.
type criterionMapping struct {
	name         string
	module       string
	supportedOps map[string]bool
	valueType    string // indicate if the value is a none, list or map	(none means no need to convert)
	mappingType  string // indicate if the value is 1-1, or 1-many relation... if 1-many, we must use policy group (like pspCompliance, image)
	// reasoning    string // Kubewarden doc URL for furhter explanation
	generateMembersFunc GenerateMembersFuncType // only available when mappingType is 1-many
	policySettingFunc   PolicySettingFunc
}

var criteriaMatrix map[string]criterionMapping

func init() {
	criteriaMatrix = buildSupportedCriteriaMatrix()
}

func buildSupportedCriteriaMatrix() map[string]criterionMapping {
	matrix := make(map[string]criterionMapping)

	addMetadataCriteria(matrix)
	addTrustedRepoCriteria(matrix)
	addUserGroupCriteria(matrix)
	addPSPCriteria(matrix)
	addHostNamespaceCriteria(matrix)
	addMiscCriteria(matrix)

	return matrix
}

func addMetadataCriteria(m map[string]criterionMapping) {
	for _, key := range []string{
		nvdata.CriteriaKeyEnvVars,
		nvdata.CriteriaKeyLabels,
		nvdata.CriteriaKeyAnnotations,
	} {
		m[key] = criterionMapping{
			name:                key,
			module:              policyCEL,
			supportedOps:        map[string]bool{nvdata.CriteriaOpContainsAny: true, nvdata.CriteriaOpContainsAll: true, nvdata.CriteriaOpNotContainsAny: true, nvdata.CriteriaOpContainsOtherThan: true},
			valueType:           valueTypeMap,
			mappingType:         mappingType1to1,
			generateMembersFunc: generatePolicyGroupMember,
			policySettingFunc:   injectCelPolicySetting,
		}
	}

	m[nvdata.CriteriaKeyNamespace] = criterionMapping{
		name:                nvdata.CriteriaKeyNamespace,
		module:              policyCEL,
		supportedOps:        map[string]bool{nvdata.CriteriaOpContainsAny: true, nvdata.CriteriaOpNotContainsAny: true},
		valueType:           valueTypeMap,
		generateMembersFunc: generatePolicyGroupMember,
		policySettingFunc:   injectCelPolicySetting,
	}
}

func addTrustedRepoCriteria(m map[string]criterionMapping) {
	for _, key := range []string{
		nvdata.CriteriaKeyImage,
		nvdata.CriteriaKeyImageRegistry,
	} {
		m[key] = criterionMapping{
			name:                key,
			module:              policyTrustedRepos,
			supportedOps:        map[string]bool{nvdata.CriteriaOpContainsAny: true, nvdata.CriteriaOpNotContainsAny: true},
			mappingType:         mappingType1to1,
			generateMembersFunc: generatePolicyGroupMember,
			policySettingFunc:   injectTrustedRepoPolicySetting,
		}
	}
}

func addUserGroupCriteria(m map[string]criterionMapping) {
	m[nvdata.CriteriaKeyUser] = criterionMapping{
		name:                nvdata.CriteriaKeyUser,
		module:              policyCEL,
		supportedOps:        map[string]bool{nvdata.CriteriaOpContainsAny: true, nvdata.CriteriaOpNotContainsAny: true, nvdata.CriteriaOpRegex: true, nvdata.CriteriaOpNotRegex: true},
		mappingType:         mappingType1to1,
		valueType:           valueTypeList,
		generateMembersFunc: generatePolicyGroupMember,
		policySettingFunc:   injectCelPolicySetting,
	}

	m[nvdata.CriteriaKeyK8sGroups] = criterionMapping{
		name:                nvdata.CriteriaKeyK8sGroups,
		module:              policyCEL,
		supportedOps:        map[string]bool{nvdata.CriteriaOpContainsAny: true, nvdata.CriteriaOpContainsAll: true, nvdata.CriteriaOpNotContainsAny: true, nvdata.CriteriaOpContainsOtherThan: true, nvdata.CriteriaOpRegex: true, nvdata.CriteriaOpNotRegex: true},
		mappingType:         mappingType1to1,
		valueType:           valueTypeList,
		generateMembersFunc: generatePolicyGroupMember,
		policySettingFunc:   injectCelPolicySetting,
	}
}

func addPSPCriteria(m map[string]criterionMapping) {
	m[nvdata.CriteriaKeyAllowPrivEscalation] = criterionMapping{
		name:                nvdata.CriteriaKeyAllowPrivEscalation,
		module:              policyAllowPrivEscalation,
		supportedOps:        map[string]bool{nvdata.CriteriaOpEqual: true},
		valueType:           valueTypeNone,
		mappingType:         mappingType1to1,
		generateMembersFunc: generatePolicyGroupMember,
	}

	m[nvdata.CriteriaKeyRunAsPrivileged] = criterionMapping{
		name:                nvdata.CriteriaKeyRunAsPrivileged,
		module:              policyPodPrivileged,
		supportedOps:        map[string]bool{nvdata.CriteriaOpEqual: true},
		valueType:           valueTypeNone,
		mappingType:         mappingType1to1,
		generateMembersFunc: generatePolicyGroupMember,
	}

	m[nvdata.CriteriaKeyRunAsRoot] = criterionMapping{
		name:                nvdata.CriteriaKeyRunAsRoot,
		module:              policyUserGroupPSP,
		supportedOps:        map[string]bool{nvdata.CriteriaOpEqual: true},
		valueType:           valueTypeNone,
		mappingType:         mappingType1to1,
		generateMembersFunc: generatePolicyGroupMember,
	}
}

func addHostNamespaceCriteria(m map[string]criterionMapping) {
	for _, key := range []string{
		nvdata.CriteriaKeySharePidWithHost,
		nvdata.CriteriaKeyShareIpcWithHost,
		nvdata.CriteriaKeyShareNetWithHost,
	} {
		m[key] = criterionMapping{
			name:                key,
			module:              policyHostNamespacesPSP,
			supportedOps:        map[string]bool{nvdata.CriteriaOpEqual: true},
			valueType:           valueTypeNone,
			mappingType:         mappingType1to1,
			generateMembersFunc: generatePolicyGroupMember,
		}
	}
}

func addMiscCriteria(m map[string]criterionMapping) {
	m[nvdata.CriteriaKeyPspCompliance] = criterionMapping{
		name:                nvdata.CriteriaKeyPspCompliance,
		supportedOps:        map[string]bool{nvdata.CriteriaOpEqual: true},
		mappingType:         mappingType1toMany,
		generateMembersFunc: generatePspComplianceMembers,
	}

	m[nvdata.CriteriaKeyEnvVarSecrets] = criterionMapping{
		name:                nvdata.CriteriaKeyEnvVarSecrets,
		module:              policyEnvSecretScanner,
		supportedOps:        map[string]bool{nvdata.CriteriaOpEqual: true},
		valueType:           valueTypeNone,
		mappingType:         mappingType1to1,
		generateMembersFunc: generatePolicyGroupMember,
	}
}

func getCriterionValueType(name string) (string, error) {
	criterion, exists := criteriaMatrix[name]
	if !exists {
		return "", fmt.Errorf("criterion not found: %s", name)
	}

	return criterion.valueType, nil
}

func getMappingType(name string) (string, error) {
	criterion, exists := criteriaMatrix[name]
	if !exists {
		return "", fmt.Errorf("mapping type not found for name: %s", name)
	}
	return criterion.mappingType, nil
}

func getModule(name string) (string, error) {
	criterion, exists := criteriaMatrix[name]
	if !exists {
		return "", fmt.Errorf("module not found for name: %s", name)
	}
	return criterion.module, nil
}

func getGenerateMembersFunc(name string) (GenerateMembersFuncType, error) {
	criterion, exists := criteriaMatrix[name]
	if !exists {
		return nil, fmt.Errorf("generate member function not found for name: %s", name)
	}
	return criterion.generateMembersFunc, nil
}

func getPolicySettingFunc(name string) (PolicySettingFunc, error) {
	criterion, exists := criteriaMatrix[name]
	if !exists {
		return nil, fmt.Errorf("policy setting function not found for name: %s", name)
	}
	return criterion.policySettingFunc, nil
}
