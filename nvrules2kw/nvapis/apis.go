package nvapis

const (
	ValidatingDenyRuleType   = "deny"
	ValidatingExceptRuleType = "exception"
	ValidatingAllowRuleType  = "allow" // same meaning as ValidatingExceptRuleType
)

type RESTAdmissionRulesData struct {
	Rules []*RESTAdmissionRule `json:"rules"`
}

type RESTAdmissionRule struct { // see type CLUSAdmissionRule
	ID         uint32                  `json:"id"`
	Category   string                  `json:"category"`
	Comment    string                  `json:"comment"`
	Criteria   []*RESTAdmRuleCriterion `json:"criteria"`
	Disable    bool                    `json:"disable"`
	Critical   bool                    `json:"critical"`
	CfgType    string                  `json:"cfg_type"`   // CfgTypeLearned / CfgTypeUserCreated / CfgTypeGround / CfgTypeFederal (see above)
	RuleType   string                  `json:"rule_type"`  // ValidatingExceptRuleType / ValidatingDenyRuleType (see above)
	RuleMode   string                  `json:"rule_mode"`  // "" / share.AdmCtrlModeMonitor / share.AdmCtrlModeProtect
	Containers []string                `json:"containers"` // empty for all containers, "containers" / "init_containers" / "ephemeral_containers"
}

type RESTAdmRuleCriterion struct { // same type CLUSAdmRuleCriterion
	Name        string                  `json:"name"`
	Op          string                  `json:"op"`
	Value       string                  `json:"value"`
	SubCriteria []*RESTAdmRuleCriterion `json:"sub_criteria,omitempty"`
	Type        string                  `json:"type,omitempty"`
	Kind        string                  `json:"template_kind,omitempty"`
	Path        string                  `json:"path,omitempty"`
	ValueType   string                  `json:"value_type,omitempty"`
}
