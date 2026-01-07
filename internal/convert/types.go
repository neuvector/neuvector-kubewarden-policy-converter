package convert

import "k8s.io/apimachinery/pkg/runtime"

type Rule struct {
	Comment  string     `yaml:"comment"   json:"comment"`
	RuleMode string     `yaml:"rule_mode" json:"rule_mode"`
	ID       int        `yaml:"id"        json:"id"`
	Criteria []Criteria `yaml:"criteria"  json:"criteria"`
}

type Criteria struct {
	Name  string `yaml:"name"  json:"name"`
	Op    string `yaml:"op"    json:"op"`
	Path  string `yaml:"path"  json:"path"`
	Value string `yaml:"value" json:"value"`
}

type Policy interface {
	runtime.Object
}

type summaryEntry struct {
	id     uint32
	status string
	notes  string
}
