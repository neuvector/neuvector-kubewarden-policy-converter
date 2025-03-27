package main

var supportedMatrix = map[string]map[string]bool{
	"envVars": {
		"containsAny":       true,
		"containsAll":       true,
		"notContainsAny":    true,
		"containsOtherThan": true,
	},
	"labels": {
		"containsAny":       true,
		"containsAll":       true,
		"notContainsAny":    true,
		"containsOtherThan": true,
	},
	"annotations": {
		"containsAny": true,
	},
	"namespace": {
		"containsAny": true,
		"containsAll": true,
	},
	"allowPrivEscalation": {"=": true},
	"runAsPrivileged":     {"=": true},
	"runAsRoot":           {"=": true},
	"shareIpcWithHost":    {"=": true},
	"shareNetWithHost":    {"=": true},
	"sharePidWithHost":    {"=": true},
	"user": {
		"containsAny": true,
		"containsAll": true,
		"regex":       true,
		"!regex":      true,
	},
	"userGroups": {
		"containsAll":       true,
		"containsAny":       true,
		"notContainsAny":    true,
		"containsOtherThan": true,
		"regex":             true,
		"!regex":            true,
	},
	"envVarSecrets": {"=": true},
	"image": {
		"containsAny":    true,
		"notContainsAny": true,
	},
	"imageRegistry": {
		"containsAny":    true,
		"notContainsAny": true,
	},
	"pspCompliance": {
		"=": true,
	},
}
