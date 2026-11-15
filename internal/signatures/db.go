package signatures

import (
	"strings"

	"sys-scanner/internal/types"
)

// registry holds all tool signatures indexed by lowercase name.
var registry map[string]types.ToolSignature

func init() {
	all := []types.ToolSignature{
		SigOpenCode,
		SigCodexCLI,
		SigClaudeCode,
		SigGitHubCopilot,
		SigCursor,
		SigWindsurf,
		SigAider,
		SigCline,
		SigRooCode,
		SigContinue,
		SigCody,
		SigTabnine,
		SigAmazonQ,
		SigCodeium,
		SigAugmentCode,
		SigHermes,
		SigZedAI,
		SigPearAI,
		SigTrae,
		SigOllama,
		SigLMStudio,
		SigGPT4All,
		SigLocalAI,
	}

	registry = make(map[string]types.ToolSignature, len(all))
	for _, sig := range all {
		registry[strings.ToLower(sig.Name)] = sig
	}
}

// Lookup returns the tool signature for the given name (case-insensitive).
// The second return value indicates whether the tool was found.
func Lookup(name string) (types.ToolSignature, bool) {
	sig, ok := registry[strings.ToLower(name)]
	return sig, ok
}

// All returns a slice of all registered tool signatures.
func All() []types.ToolSignature {
	result := make([]types.ToolSignature, 0, len(registry))
	for _, sig := range registry {
		result = append(result, sig)
	}
	return result
}

// BinaryNames returns the deduplicated set of all binary names across all
// registered tool signatures, lowercased.
func BinaryNames() []string {
	seen := make(map[string]struct{})
	var result []string
	for _, sig := range All() {
		for _, name := range sig.BinaryNames {
			lower := strings.ToLower(name)
			if _, ok := seen[lower]; !ok {
				seen[lower] = struct{}{}
				result = append(result, lower)
			}
		}
	}
	return result
}
