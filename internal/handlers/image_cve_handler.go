package handlers

import (
	"encoding/json"
	"fmt"
	"strconv"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/neuvector/neuvector-kubewarden-policy-converter/internal/share"
	nvapis "github.com/neuvector/neuvector/controller/api"
	nvdata "github.com/neuvector/neuvector/share"
)

type ImageCVEHandler struct {
	BasePolicyHandler

	// criteriaNegationMap maps criteria operations to their negated forms for deny-action neuvector rule conversion.
	// Since converter only support deny actions, positive criteria must be converted to negative counterparts.
	criteriaNegationMap map[string]string
	vulReportNamespace  string
	platform            string
}

type CVESeveritySettings struct {
	Total *int `json:"total,omitempty"`
}

type PlatformSettings struct {
	Arch string `json:"arch,omitempty"`
	OS   string `json:"os"`
}

type MaxSeveritySettings struct {
	High   *CVESeveritySettings `json:"high,omitempty"`
	Medium *CVESeveritySettings `json:"medium,omitempty"`
}

type CVESettings struct {
	IgnoreMissingVulnerabilityReport *bool                `json:"ignoreMissingVulnerabilityReport,omitempty"`
	VulnerabilityReportNamespace     string               `json:"vulnerabilityReportNamespace,omitempty"`
	MaxSeverity                      *MaxSeveritySettings `json:"maxSeverity,omitempty"`
	Platform                         *PlatformSettings    `json:"platform,omitempty"`
}

const (
	ImageCVEPolicyURI = "registry://ghcr.io/kubewarden/policies/image-cve-policy:v0.5.0"

	RuleImageScanned = "imageScanned"
	RuleHighCVECount = "cveHighCount"
	RuleMedCVECount  = "cveMediumCount"
)

func NewImageCVEHandler(vulReportNamespace string, platform string) *ImageCVEHandler {
	return &ImageCVEHandler{
		BasePolicyHandler: BasePolicyHandler{
			Unsupported: false,
			SupportedOps: map[string]bool{
				nvdata.CriteriaOpBiggerEqualThan: true,
				nvdata.CriteriaOpEqual:           true,
			},
			Name:               share.ExtractModuleName(ImageCVEPolicyURI),
			Module:             ImageCVEPolicyURI,
			ApplicableResource: ResourceWorkload,
			ContextAwareResources: []policiesv1.ContextAwareResource{
				{
					Kind:       "VulnerabilityReport",
					APIVersion: "storage.sbomscanner.kubewarden.io/v1alpha1",
				},
			},
		},
		criteriaNegationMap: map[string]string{
			nvdata.CriteriaOpContainsAll:       "doesNotContainAllOf",
			nvdata.CriteriaOpContainsAny:       "doesNotContainAnyOf",
			nvdata.CriteriaOpContainsOtherThan: "doesNotContainOtherThan",
			nvdata.CriteriaOpNotContainsAny:    "containsAnyOf",
		},
		vulReportNamespace: vulReportNamespace,
		platform:           platform,
	}
}

func (h *ImageCVEHandler) BuildPolicySettings(criteria []*nvapis.RESTAdmRuleCriterion) ([]byte, error) {
	settings := CVESettings{}
	settings.VulnerabilityReportNamespace = h.vulReportNamespace
	settings.MaxSeverity = &MaxSeveritySettings{}
	settings.Platform = &PlatformSettings{
		OS:   "linux",
		Arch: h.platform,
	}

	for _, criterion := range criteria {
		switch criterion.Name {
		case RuleImageScanned:
			requireImageScanned, err := strconv.ParseBool(criterion.Value)
			if err != nil {
				return nil, err
			}

			settings.IgnoreMissingVulnerabilityReport = &requireImageScanned
		case RuleHighCVECount:
			// NeuVector interprets "high CVEs ≤ X" to tolerate 0..(X-1), rejecting at X.
			// To match this in Kubewarden, set max to (X-1).
			threshold, err := strconv.Atoi(criterion.Value)
			if err != nil {
				return nil, fmt.Errorf("invalid %s value %q: %w", criterion.Name, criterion.Value, err)
			}
			maxAccepted := threshold - 1
			settings.MaxSeverity.High = &CVESeveritySettings{Total: &maxAccepted}
		case RuleMedCVECount:
			// NeuVector interprets "medium CVEs ≤ X" to tolerate 0..(X-1), rejecting at X.
			// To match this in Kubewarden, set max to (X-1).
			threshold, err := strconv.Atoi(criterion.Value)
			if err != nil {
				return nil, fmt.Errorf("invalid %s value %q: %w", criterion.Name, criterion.Value, err)
			}
			maxAccepted := threshold - 1
			settings.MaxSeverity.Medium = &CVESeveritySettings{Total: &maxAccepted}
		default:
			return nil, fmt.Errorf("unsupported criterion: %s", criterion.Name)
		}
	}

	if settings.MaxSeverity.High == nil && settings.MaxSeverity.Medium == nil {
		settings.MaxSeverity = nil
	}

	return json.Marshal(settings)
}
