package share

const (
	MsgNeuVectorRuleOnly           = "neuvector environment only rule"
	MsgOnlyDenyRuleSupported       = `only "deny" rule supported`
	MsgRuleDisabled                = `rule is disabled`
	MsgRuleConvertedSuccessfully   = "rule converted successfully"
	MsgUnsupportedRuleCriteria     = "unsupported criteria"
	MsgUnsupportedCriteriaOperator = "unsupported operator"
	MsgRuleParsingError            = "failed to parse rule"
	MsgRuleGenerateKWPolicyError   = "failed to generate Kubewarden policy"
)

const (
	// CriteriaDoesNotContainAllOf is the Kubewarden policy criteria operation for "does not contain all of".
	CriteriaDoesNotContainAllOf = "doesNotContainAllOf"
	// CriteriaDoesNotContainAnyOf is the Kubewarden policy criteria operation for "does not contain any of".
	CriteriaDoesNotContainAnyOf = "doesNotContainAnyOf"
	// CriteriaDoesNotContainOtherThan is the Kubewarden policy criteria operation for "does not contain other than".
	CriteriaDoesNotContainOtherThan = "doesNotContainOtherThan"
	// CriteriaContainsAnyOf is the Kubewarden policy criteria operation for "contains any of".
	CriteriaContainsAnyOf = "containsAnyOf"
)

const (
	// RBACFieldAPIGroups is the RBAC field key for API groups.
	RBACFieldAPIGroups = "apiGroups"
	// RBACFieldResources is the RBAC field key for resources.
	RBACFieldResources = "resources"
	// RBACFieldVerbs is the RBAC field key for verbs.
	RBACFieldVerbs = "verbs"
)

const (
	// ValueTrue represents the string "true".
	ValueTrue = "true"
)
