package share

import (
	"bytes"
	"encoding/json"
	"strings"
)

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

func ConvertBytesToJSON(b []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return bytes.TrimSpace(b), err
	}
	cb, err := json.Marshal(v)
	return cb, err
}
