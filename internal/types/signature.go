package types

// ToolSignature defines the detection signature for a known AI tool.
type ToolSignature struct {
	Name         string              `json:"name"`
	DisplayName  string              `json:"display_name"`
	Category     string              `json:"category"`
	BinaryNames  []string            `json:"binary_names"`
	ConfigDirs   map[string][]string `json:"config_dirs"`
	ExtensionIDs []string            `json:"extension_ids"`
	ProcessNames []string            `json:"process_names"`
	Ports        []int               `json:"ports"`
}
