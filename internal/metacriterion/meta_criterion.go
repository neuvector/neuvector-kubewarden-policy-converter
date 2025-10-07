package metacriterion

import nvapis "github.com/neuvector/neuvector/controller/api"

// MetaCriterion represents a composite criterion that expands into multiple basic criteria.
type MetaCriterion interface {
	// Expand returns the list of basic criteria that this meta criterion represents.
	// These expanded criteria will replace the original meta criterion in the rule.
	Expand() []*nvapis.RESTAdmRuleCriterion

	// GetSupportedOps returns a map of supported operators for this criterion
	GetSupportedOps() map[string]bool
}
