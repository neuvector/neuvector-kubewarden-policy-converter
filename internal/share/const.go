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

	PolicyCELURI                    = "registry://ghcr.io/kubewarden/policies/cel-policy:latest"
	PolicyHostNamespacesPSPURI      = "registry://ghcr.io/kubewarden/policies/host-namespaces-psp:v1.1.0"
	PolicyAllowPrivEscalationURI    = "registry://ghcr.io/kubewarden/policies/allow-privilege-escalation-psp:v1.0.0"
	PolicyPodPrivilegedURI          = "registry://ghcr.io/kubewarden/policies/pod-privileged:v1.0.3"
	PolicyContainerRunningAsUserURI = "registry://ghcr.io/kubewarden/policies/container-running-as-user:v1.0.4"
	PolicyTrustedReposURI           = "registry://ghcr.io/kubewarden/policies/trusted-repos:v0.2.0"
	PolicyEnvSecretScannerURI       = "registry://ghcr.io/kubewarden/policies/env-variable-secrets-scanner:v1.0.5" // #nosec G101 - This is a policy registry URL, not a secret
	PolicyEnvironmentVariableURI    = "registry://ghcr.io/kubewarden/policies/environment-variable-policy:v3.0.1"
	PolicyAnnotationsPolicyURI      = "registry://ghcr.io/kubewarden/policies/annotations:v0.1.0"
)
