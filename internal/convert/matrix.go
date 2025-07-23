/*
Copyright (c) 2025 SUSE LLC

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
	"os"
	"sort"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
	"github.com/olekukonko/tablewriter"
)

// Kubewarden policy modules.
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

	nvPreserveID = 1000 // Rule IDs under 1000 are reserved for NeuVector internal rules and should not be used in non-NeuVector environments.
	// mappingType1to1    = "1-1"
	// mappingType1toMany = "1-many".
)

// GenerateMembersFuncType returns members for policy group mapping.
type GenerateMembersFuncType func(criterion *nvapis.RESTAdmRuleCriterion) ([]policiesv1.PolicyGroupMemberWithContext, error)

// PolicySettingFunc injects policy-specific settings into a YAML object.
type PolicySettingFunc func(criterion *nvapis.RESTAdmRuleCriterion, yamlObj map[string]interface{}) error

// criterionMapping defines how each NeuVector criterion maps to Kubewarden.
type criterionMapping struct {
	name                string
	displayName         string // display name for the criterion
	module              string
	supportedOps        map[string]bool
	valueType           string                  // indicate if the value is a none, list or map	(none means no need to convert)
	isOneToMany         bool                    //  if true, we must use policy group (like pspCompliance, image)
	generateMembersFunc GenerateMembersFuncType // only available when mappingType is 1-many
	policySettingFunc   PolicySettingFunc

	unsupported      bool
	relatedPolicyURL string // we can provide related KW policy URL, if it is not supported user can check the most relevant KW policy
}

type CriteriaMatrix struct {
	data      map[string]criterionMapping
	converter *RuleConverter
}

func NewCriteriaMatrix(rc *RuleConverter) *CriteriaMatrix {
	cm := &CriteriaMatrix{
		converter: rc,
	}
	cm.data = cm.buildSupportedCriteriaMatrix()
	return cm
}

func (cm *CriteriaMatrix) buildSupportedCriteriaMatrix() map[string]criterionMapping {
	matrix := make(map[string]criterionMapping)

	cm.addMetadataCriteria(matrix)
	cm.addTrustedRepoCriteria(matrix)
	cm.addUserGroupCriteria(matrix)
	cm.addPSPCriteria(matrix)
	cm.addHostNamespaceCriteria(matrix)
	cm.addMiscCriteria(matrix)

	cm.addUnsupportedCriteria(matrix)

	return matrix
}

func (cm *CriteriaMatrix) addUnsupportedCriteria(m map[string]criterionMapping) {
	for key, value := range map[string]string{
		nvdata.CriteriaKeyCustomPath:          "Add customized criterion",
		nvdata.CriteriaKeyCVEHighCount:        "Count of high severity CVE",
		nvdata.CriteriaKeyCVEHighWithFixCount: "Count of high severity CVE with fix",

		nvdata.CriteriaKeyCVEMediumCount:  "Count of medium severity CVE",
		nvdata.CriteriaKeyCVENames:        "CVE names",
		nvdata.CriteriaKeyCVEScore:        "CVE score",
		nvdata.CriteriaKeyImageCompliance: "Image compliance violations",
		nvdata.CriteriaKeyImageNoOS:       "Image without OS information",

		nvdata.CriteriaKeyImageScanned:   "Image scanned",
		nvdata.CriteriaKeyImageSigned:    "Image signed",
		nvdata.CriteriaKeyImageVerifiers: "Image Sigstore Verifiers",

		nvdata.CriteriaKeyModules:      "Modules",
		nvdata.CriteriaKeyMountVolumes: "Mount Volumes",

		nvdata.CriteriaKeyRequestLimit:     "Resource Limit Configuration (RLC)",
		nvdata.CriteriaKeySaBindRiskyRole:  "Service Account Bound High Risk Role",
		nvdata.CriteriaKeyStorageClassName: "StorageClass Name",
		nvdata.CriteriaKeyHasPssViolation:  "Violates PSA policy",
	} {
		m[key] = criterionMapping{
			name:        key,
			displayName: value,
			unsupported: true,
		}
	}

	m[nvdata.CriteriaKeyNamespace] = criterionMapping{
		name:                nvdata.CriteriaKeyNamespace,
		displayName:         "Namespace",
		module:              policyCEL,
		supportedOps:        map[string]bool{nvdata.CriteriaOpContainsAny: true, nvdata.CriteriaOpNotContainsAny: true},
		valueType:           valueTypeMap,
		generateMembersFunc: cm.converter.generatePolicyGroupMembers,
		policySettingFunc:   cm.converter.injectCelPolicySetting,
	}
}

// nvdata.CriteriaKeyCustomPath 			Add customized criterion ...
// [x] Allow Privilege Escalation
// [x] Annotations
// nvdata.CriteriaKeyCVEHighCount			Count of high severity CVE
// CriteriaKeyCVEHighWithFixCount			Count of high severity CVE with fix
// CriteriaKeyCVEMediumCount				Count of medium severity CVE
// CriteriaKeyCVENames						CVE names
// CriteriaKeyCVEScore						CVE score
// [x] Environment variables with secrets
// [x] Environment variables
// [x] Image

// CriteriaKeyImageCompliance				Image compliance violations
// CriteriaKeyImageNoOS						Image without OS information
// [x] Image registry

// CriteriaKeyImageScanned					Image scanned
// CriteriaKeyImageSigned					Image signed
// CriteriaKeyImageVerifiers				Image Sigstore Verifiers
// [x] Labels

// CriteriaKeyModules						Modules
// CriteriaKeyMountVolumes					Mount Volumes
// [x] Namespace
// [x] PSP Best Practice

// CriteriaKeyRequestLimit					Resource Limit Configuration (RLC)
// [x] Run as privileged
// [x] Run as root
// CriteriaKeySaBindRiskyRole				Service Account Bound High Risk Role
// [x] Share host's IPC namespaces
// [x] Share host's Network
// [x] Share host's PID namespaces
// CriteriaKeyStorageClassName				StorageClass Name
// [x] User
// [x] User groups
// CriteriaKeyHasPssViolation				 Violates PSA policy

func (cm *CriteriaMatrix) addMetadataCriteria(m map[string]criterionMapping) {
	for key, value := range map[string]string{
		nvdata.CriteriaKeyEnvVars:     "Environment variables",
		nvdata.CriteriaKeyLabels:      "Labels",
		nvdata.CriteriaKeyAnnotations: "Annotations",
	} {
		m[key] = criterionMapping{
			name:        key,
			displayName: value,
			module:      policyCEL,
			supportedOps: map[string]bool{
				nvdata.CriteriaOpContainsAny:       true,
				nvdata.CriteriaOpContainsAll:       true,
				nvdata.CriteriaOpNotContainsAny:    true,
				nvdata.CriteriaOpContainsOtherThan: true,
			},
			valueType:           valueTypeMap,
			generateMembersFunc: cm.converter.generatePolicyGroupMembers,
			policySettingFunc:   cm.converter.injectCelPolicySetting,
		}
	}

	m[nvdata.CriteriaKeyNamespace] = criterionMapping{
		name:                nvdata.CriteriaKeyNamespace,
		displayName:         "Namespace",
		module:              policyCEL,
		supportedOps:        map[string]bool{nvdata.CriteriaOpContainsAny: true, nvdata.CriteriaOpNotContainsAny: true},
		valueType:           valueTypeMap,
		generateMembersFunc: cm.converter.generatePolicyGroupMembers,
		policySettingFunc:   cm.converter.injectCelPolicySetting,
	}
}

func (cm *CriteriaMatrix) addTrustedRepoCriteria(m map[string]criterionMapping) {
	for key, value := range map[string]string{
		nvdata.CriteriaKeyImage:         "Image",
		nvdata.CriteriaKeyImageRegistry: "Image registry",
	} {
		m[key] = criterionMapping{
			name:        key,
			displayName: value,
			module:      policyTrustedRepos,
			supportedOps: map[string]bool{
				nvdata.CriteriaOpContainsAny:    true,
				nvdata.CriteriaOpNotContainsAny: true,
			},
			generateMembersFunc: cm.converter.generatePolicyGroupMembers,
			policySettingFunc:   cm.converter.injectTrustedRepoPolicySetting,
		}
	}
}

func (cm *CriteriaMatrix) addUserGroupCriteria(m map[string]criterionMapping) {
	m[nvdata.CriteriaKeyUser] = criterionMapping{
		name:        nvdata.CriteriaKeyUser,
		displayName: "User",
		module:      policyCEL,
		supportedOps: map[string]bool{
			nvdata.CriteriaOpContainsAny:    true,
			nvdata.CriteriaOpNotContainsAny: true,
			nvdata.CriteriaOpRegex:          true,
			nvdata.CriteriaOpNotRegex:       true,
		},
		valueType:           valueTypeList,
		generateMembersFunc: cm.converter.generatePolicyGroupMembers,
		policySettingFunc:   cm.converter.injectCelPolicySetting,
	}

	m[nvdata.CriteriaKeyK8sGroups] = criterionMapping{
		name:        nvdata.CriteriaKeyK8sGroups,
		displayName: "User groups",
		module:      policyCEL,
		supportedOps: map[string]bool{
			nvdata.CriteriaOpContainsAny:       true,
			nvdata.CriteriaOpContainsAll:       true,
			nvdata.CriteriaOpNotContainsAny:    true,
			nvdata.CriteriaOpContainsOtherThan: true,
			nvdata.CriteriaOpRegex:             true,
			nvdata.CriteriaOpNotRegex:          true,
		},
		valueType:           valueTypeList,
		generateMembersFunc: cm.converter.generatePolicyGroupMembers,
		policySettingFunc:   cm.converter.injectCelPolicySetting,
	}
}

func (cm *CriteriaMatrix) addPSPCriteria(m map[string]criterionMapping) {
	m[nvdata.CriteriaKeyAllowPrivEscalation] = criterionMapping{
		name:                nvdata.CriteriaKeyAllowPrivEscalation,
		displayName:         "Allow Privilege Escalation",
		module:              policyAllowPrivEscalation,
		supportedOps:        map[string]bool{nvdata.CriteriaOpEqual: true},
		valueType:           valueTypeNone,
		generateMembersFunc: cm.converter.generatePolicyGroupMembers,
	}

	m[nvdata.CriteriaKeyRunAsPrivileged] = criterionMapping{
		name:                nvdata.CriteriaKeyRunAsPrivileged,
		displayName:         "Run as privileged",
		module:              policyPodPrivileged,
		supportedOps:        map[string]bool{nvdata.CriteriaOpEqual: true},
		valueType:           valueTypeNone,
		generateMembersFunc: cm.converter.generatePolicyGroupMembers,
	}

	m[nvdata.CriteriaKeyRunAsRoot] = criterionMapping{
		name:                nvdata.CriteriaKeyRunAsRoot,
		displayName:         "Run as root",
		module:              policyUserGroupPSP,
		supportedOps:        map[string]bool{nvdata.CriteriaOpEqual: true},
		valueType:           valueTypeNone,
		generateMembersFunc: cm.converter.generatePolicyGroupMembers,
	}
}

func (cm *CriteriaMatrix) addHostNamespaceCriteria(m map[string]criterionMapping) {
	for key, value := range map[string]string{
		nvdata.CriteriaKeySharePidWithHost: "Share host's PID namespaces",
		nvdata.CriteriaKeyShareIpcWithHost: "Share host's IPC namespaces",
		nvdata.CriteriaKeyShareNetWithHost: "Share host's Network",
	} {
		m[key] = criterionMapping{
			name:                key,
			displayName:         value,
			module:              policyHostNamespacesPSP,
			supportedOps:        map[string]bool{nvdata.CriteriaOpEqual: true},
			valueType:           valueTypeNone,
			generateMembersFunc: cm.converter.generatePolicyGroupMembers,
		}
	}
}

func (cm *CriteriaMatrix) addMiscCriteria(m map[string]criterionMapping) {
	m[nvdata.CriteriaKeyPspCompliance] = criterionMapping{
		name:                nvdata.CriteriaKeyPspCompliance,
		displayName:         "PSP Best Practice",
		supportedOps:        map[string]bool{nvdata.CriteriaOpEqual: true},
		isOneToMany:         true,
		generateMembersFunc: cm.converter.generatePspComplianceMembers,
	}

	m[nvdata.CriteriaKeyEnvVarSecrets] = criterionMapping{
		name:                nvdata.CriteriaKeyEnvVarSecrets,
		displayName:         "Environment variables with secrets",
		module:              policyEnvSecretScanner,
		supportedOps:        map[string]bool{nvdata.CriteriaOpEqual: true},
		valueType:           valueTypeNone,
		generateMembersFunc: cm.converter.generatePolicyGroupMembers,
	}
}

func (cm *CriteriaMatrix) GetCriterionValueType(name string) (string, error) {
	criterion, exists := cm.data[name]
	if !exists {
		return "", fmt.Errorf("criterion not found: %s", name)
	}

	return criterion.valueType, nil
}

// func (cm *CriteriaMatrix) GetMappingType(name string) (string, error) {
// 	criterion, exists := cm.data[name]
// 	if !exists {
// 		return "", fmt.Errorf("mapping type not found for name: %s", name)
// 	}
// 	return criterion.mappingType, nil
// }

func (cm *CriteriaMatrix) IsOneToMany(name string) (bool, error) {
	criterion, exists := cm.data[name]
	if !exists {
		return false, fmt.Errorf("mapping type not found for name: %s", name)
	}
	return criterion.isOneToMany, nil
}

func (cm *CriteriaMatrix) GetModule(name string) (string, error) {
	criterion, exists := cm.data[name]
	if !exists {
		return "", fmt.Errorf("module not found for name: %s", name)
	}
	return criterion.module, nil
}

func (cm *CriteriaMatrix) GetGenerateMembersFunc(name string) (GenerateMembersFuncType, error) {
	criterion, exists := cm.data[name]
	if !exists {
		return nil, fmt.Errorf("generate member function not found for name: %s", name)
	}
	return criterion.generateMembersFunc, nil
}

func (cm *CriteriaMatrix) GetPolicySettingFunc(name string) (PolicySettingFunc, error) {
	criterion, exists := cm.data[name]
	if !exists {
		return nil, fmt.Errorf("policy setting function not found for name: %s", name)
	}
	return criterion.policySettingFunc, nil
}

func (cm *CriteriaMatrix) isSupportedRule(rule *nvapis.RESTAdmissionRule) (bool, string) {
	if rule.ID < nvPreserveID {
		return false, MsgNeuVectorRuleOnly
	}

	// Only support Deny rules.
	if rule.RuleType != nvapis.ValidatingDenyRuleType {
		return false, MsgOnlyDenyRuleSupported
	}

	for _, rule := range rule.Criteria {
		criterion, exists := cm.data[rule.Name]
		if !exists {
			return false, MsgUnsupportedRuleCriteria
		}

		if criterion.unsupported {
			return false, MsgUnsupportedRuleCriteria
		}

		// criteria is supported, now check it's operator
		if !criterion.supportedOps[rule.Op] {
			return false, MsgUnsupportedCriteriaOperator
		}
	}

	// Rule is supported if all checks passed.
	return true, ""
}

func (cm *CriteriaMatrix) dumpSupportedCriteriaTable() {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetColWidth(defaultColumnWidth)
	table.SetHeader([]string{"Criterion Name", "Supported", "Note"})

	var mappings []criterionMapping
	for _, mapping := range cm.data {
		mappings = append(mappings, mapping)
	}

	sort.Slice(mappings, func(i, j int) bool {
		return mappings[i].name < mappings[j].name
	})

	for _, mapping := range mappings {
		supportStatus := "Yes"
		if mapping.unsupported {
			supportStatus = "No"
		}
		table.Append([]string{mapping.displayName, supportStatus, mapping.relatedPolicyURL})
	}

	table.Render()
}
