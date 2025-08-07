package share

import "strings"

func ExtractModuleName(module string) string {
	// remove the registry:// prefix
	if idx := strings.Index(module, "://"); idx != -1 {
		module = module[idx+3:]
	}

	if idx := strings.LastIndex(module, ":"); idx != -1 {
		module = module[:idx]
	}
	parts := strings.Split(module, "/")
	module = parts[len(parts)-1]
	module = strings.ReplaceAll(module, "-", "_")
	return module
}
