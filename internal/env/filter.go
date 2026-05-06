package env

import "strings"

type Config struct {
	AllowList  []string `json:"allow_list" yaml:"allow_list"`
	BlockList  []string `json:"block_list" yaml:"block_list"`
	RedactList []string `json:"redact_list" yaml:"redact_list"`
}

func Filter(values []string, config Config) []string {
	allowSet := makeSet(config.AllowList)
	blockSet := makeSet(config.BlockList)
	redactSet := makeSet(config.RedactList)

	filtered := make([]string, 0, len(values))
	for _, value := range values {
		key := envKey(value)
		if len(allowSet) > 0 && !allowSet[key] {
			continue
		}
		if blockSet[key] {
			continue
		}
		if redactSet[key] {
			filtered = append(filtered, key+"="+dummyValue(key))
			continue
		}
		filtered = append(filtered, value)
	}
	return filtered
}

func Set(values []string, key string, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(values)+1)
	replaced := false
	for _, item := range values {
		if strings.HasPrefix(item, prefix) {
			result = append(result, prefix+value)
			replaced = true
			continue
		}
		result = append(result, item)
	}
	if !replaced {
		result = append(result, prefix+value)
	}
	return result
}

func Get(values []string, key string) string {
	prefix := key + "="
	for _, item := range values {
		if strings.HasPrefix(item, prefix) {
			return strings.TrimPrefix(item, prefix)
		}
	}
	return ""
}

func makeSet(values []string) map[string]bool {
	result := make(map[string]bool)
	for _, value := range values {
		result[value] = true
	}
	return result
}

func envKey(value string) string {
	separatorIndex := strings.Index(value, "=")
	if separatorIndex < 0 {
		return value
	}
	return value[:separatorIndex]
}

func dummyValue(key string) string {
	switch key {
	case "DATABASE_URL":
		return "postgres://user:***@localhost:5432/db"
	case "API_ENDPOINT":
		return "https://api.***.com"
	default:
		return "[REDACTED]"
	}
}
