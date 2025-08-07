package share

const (
	MsgNeuVectorRuleOnly           = "neuvector environment only rule"
	MsgOnlyDenyRuleSupported       = `only "deny" rule supported`
	MsgRuleDisabled                = `rule is disabled`
	MsgRuleConvertedSuccessfully   = "rule converted successfully"
	MsgUnsupportedRuleCriteria     = "unsupported criteria"
	MsgUnsupportedCriteriaOperator = "unsupported operator"
	MsgRuleParsingError            = "failed to parse rule"
	MsgRuleGenerateKWPolicyError   = "failed to generate Kubewarden poilcy"

	PolicyCELURI                 = "registry://ghcr.io/kubewarden/policies/cel-policy:latest"
	PolicyHostNamespacesPSPURI   = "registry://ghcr.io/kubewarden/policies/host-namespaces-psp:v1.1.0"
	PolicyAllowPrivEscalationURI = "registry://ghcr.io/kubewarden/policies/allow-privilege-escalation-psp:v0.2.6"
	PolicyPodPrivilegedURI       = "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.3.3"
	PolicyUserGroupPSPURI        = "registry://ghcr.io/kubewarden/policies/user-group-psp:v0.6.3"
	PolicyTrustedReposURI        = "registry://ghcr.io/kubewarden/policies/trusted-repos:v0.2.0"
	PolicyEnvSecretScannerURI    = "registry://ghcr.io/kubewarden/policies/env-variable-secrets-scanner:v0.1.8" // #nosec G101
)
