// Package signatures provides detection signatures for known AI tools.
package signatures

import "sys-scanner/internal/types"

// --- AI Coding Assistants ---

// SigOpenCode is the detection signature for OpenCode.
var SigOpenCode = types.ToolSignature{
	Name:        "opencode",
	DisplayName: "OpenCode",
	Category:    "coding-assistant",
	BinaryNames: []string{"opencode"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.config/opencode"},
		"darwin":  {"~/.config/opencode"},
		"windows": {`%APPDATA%\opencode`},
	},
}

// SigCodexCLI is the detection signature for Codex CLI.
var SigCodexCLI = types.ToolSignature{
	Name:        "codex-cli",
	DisplayName: "Codex CLI",
	Category:    "coding-assistant",
	BinaryNames: []string{"codex"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.codex"},
		"darwin":  {"~/.codex"},
		"windows": {"~/.codex"},
	},
}

// SigClaudeCode is the detection signature for Claude Code.
var SigClaudeCode = types.ToolSignature{
	Name:        "claude-code",
	DisplayName: "Claude Code",
	Category:    "coding-assistant",
	BinaryNames: []string{"claude"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.claude"},
		"darwin":  {"~/.claude"},
		"windows": {"~/.claude"},
	},
}

// SigGitHubCopilot is the detection signature for GitHub Copilot.
var SigGitHubCopilot = types.ToolSignature{
	Name:         "github-copilot",
	DisplayName:  "GitHub Copilot",
	Category:     "coding-assistant",
	ExtensionIDs: []string{"github.copilot"},
	ProcessNames: []string{"copilot-agent"},
}

// SigAider is the detection signature for Aider.
var SigAider = types.ToolSignature{
	Name:        "aider",
	DisplayName: "Aider",
	Category:    "coding-assistant",
	BinaryNames: []string{"aider"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.aider"},
		"darwin":  {"~/.aider"},
		"windows": {"~/.aider"},
	},
}

// SigCline is the detection signature for Cline.
var SigCline = types.ToolSignature{
	Name:         "cline",
	DisplayName:  "Cline",
	Category:     "coding-assistant",
	ExtensionIDs: []string{"saoudrizwan.claude-dev"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.cline"},
		"darwin":  {"~/.cline"},
		"windows": {"~/.cline"},
	},
}

// SigRooCode is the detection signature for Roo Code.
var SigRooCode = types.ToolSignature{
	Name:         "roo-code",
	DisplayName:  "Roo Code",
	Category:     "coding-assistant",
	ExtensionIDs: []string{"rooveterinaryinc.roo-cline"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.roo"},
		"darwin":  {"~/.roo"},
		"windows": {"~/.roo"},
	},
}

// SigContinue is the detection signature for Continue.
var SigContinue = types.ToolSignature{
	Name:         "continue",
	DisplayName:  "Continue",
	Category:     "coding-assistant",
	ExtensionIDs: []string{"continue.continue"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.continue"},
		"darwin":  {"~/.continue"},
		"windows": {"~/.continue"},
	},
}

// SigCody is the detection signature for Cody.
var SigCody = types.ToolSignature{
	Name:         "cody",
	DisplayName:  "Cody",
	Category:     "coding-assistant",
	BinaryNames:  []string{"cody"},
	ExtensionIDs: []string{"sourcegraph.cody-ai"},
}

// SigTabnine is the detection signature for Tabnine.
var SigTabnine = types.ToolSignature{
	Name:         "tabnine",
	DisplayName:  "Tabnine",
	Category:     "coding-assistant",
	BinaryNames:  []string{"TabNine"},
	ExtensionIDs: []string{"TabNine.tabnine-vscode"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.tabnine"},
		"darwin":  {"~/.tabnine"},
		"windows": {"~/.tabnine"},
	},
}

// SigAmazonQ is the detection signature for Amazon Q Developer.
var SigAmazonQ = types.ToolSignature{
	Name:         "amazon-q",
	DisplayName:  "Amazon Q Developer",
	Category:     "coding-assistant",
	BinaryNames:  []string{"q"},
	ExtensionIDs: []string{"AmazonWebServices.amazon-q-vscode"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.aws/amazonq"},
		"darwin":  {"~/.aws/amazonq"},
		"windows": {"~/.aws/amazonq"},
	},
}

// SigCodeium is the detection signature for Codeium.
var SigCodeium = types.ToolSignature{
	Name:         "codeium",
	DisplayName:  "Codeium",
	Category:     "coding-assistant",
	ExtensionIDs: []string{"Codeium.codeium"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.codeium"},
		"darwin":  {"~/.codeium"},
		"windows": {"~/.codeium"},
	},
}

// SigAugmentCode is the detection signature for Augment Code.
var SigAugmentCode = types.ToolSignature{
	Name:         "augment-code",
	DisplayName:  "Augment Code",
	Category:     "coding-assistant",
	BinaryNames:  []string{"auggie"},
	ExtensionIDs: []string{"augment.vscode-augment"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.augment"},
		"darwin":  {"~/.augment"},
		"windows": {"~/.augment"},
	},
}

// SigHermes is the detection signature for Hermes AI agent.
var SigHermes = types.ToolSignature{
	Name:         "hermes",
	DisplayName:  "Hermes",
	Category:     "coding-assistant",
	BinaryNames:  []string{"hermes"},
	ProcessNames: []string{"hermes"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.hermes"},
		"darwin":  {"~/.hermes"},
		"windows": {"~/.hermes"},
	},
}

// --- AI Editors / IDEs ---

// SigCursor is the detection signature for Cursor.
var SigCursor = types.ToolSignature{
	Name:        "cursor",
	DisplayName: "Cursor",
	Category:    "ai-editor",
	BinaryNames: []string{"cursor"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.cursor", "~/.config/Cursor"},
		"darwin":  {"~/.cursor", "~/.config/Cursor"},
		"windows": {`~/.cursor`},
	},
}

// SigWindsurf is the detection signature for Windsurf.
var SigWindsurf = types.ToolSignature{
	Name:        "windsurf",
	DisplayName: "Windsurf",
	Category:    "ai-editor",
	BinaryNames: []string{"windsurf"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.codeium/windsurf"},
		"darwin":  {"~/.codeium/windsurf"},
		"windows": {"~/.codeium/windsurf"},
	},
}

// SigZedAI is the detection signature for Zed AI.
var SigZedAI = types.ToolSignature{
	Name:        "zed-ai",
	DisplayName: "Zed AI",
	Category:    "ai-editor",
	BinaryNames: []string{"zed"},
	ConfigDirs: map[string][]string{
		"linux":  {"~/.config/zed"},
		"darwin": {"~/.config/zed"},
	},
}

// SigPearAI is the detection signature for PearAI.
var SigPearAI = types.ToolSignature{
	Name:        "pearai",
	DisplayName: "PearAI",
	Category:    "ai-editor",
	BinaryNames: []string{"pearai"},
	ConfigDirs: map[string][]string{
		"linux":  {"~/.config/pear"},
		"darwin": {"~/.config/pear"},
	},
}

// SigTrae is the detection signature for Trae.
var SigTrae = types.ToolSignature{
	Name:        "trae",
	DisplayName: "Trae",
	Category:    "ai-editor",
	BinaryNames: []string{"trae"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.config/Trae", "~/.trae"},
		"darwin":  {"~/.config/Trae", "~/.trae"},
		"windows": {"~/.config/Trae"},
	},
}

// --- Local LLM Runners ---

// SigOllama is the detection signature for Ollama.
var SigOllama = types.ToolSignature{
	Name:         "ollama",
	DisplayName:  "Ollama",
	Category:     "local-llm",
	BinaryNames:  []string{"ollama"},
	ProcessNames: []string{"ollama"},
	Ports:        []int{11434},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.ollama"},
		"darwin":  {"~/.ollama"},
		"windows": {"~/.ollama"},
	},
}

// SigLMStudio is the detection signature for LM Studio.
var SigLMStudio = types.ToolSignature{
	Name:         "lm-studio",
	DisplayName:  "LM Studio",
	Category:     "local-llm",
	ProcessNames: []string{"LM Studio"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.lmstudio", "~/.cache/lm-studio"},
		"darwin":  {"~/.lmstudio", "~/.cache/lm-studio"},
		"windows": {"~/.lmstudio"},
	},
}

// SigGPT4All is the detection signature for GPT4All.
var SigGPT4All = types.ToolSignature{
	Name:        "gpt4all",
	DisplayName: "GPT4All",
	Category:    "local-llm",
	BinaryNames: []string{"gpt4all"},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.config/nomic.ai"},
		"darwin":  {"~/.config/nomic.ai"},
		"windows": {"~/.config/nomic.ai"},
	},
}

// SigLocalAI is the detection signature for LocalAI.
var SigLocalAI = types.ToolSignature{
	Name:        "localai",
	DisplayName: "LocalAI",
	Category:    "local-llm",
	BinaryNames: []string{"local-ai"},
	Ports:       []int{8080},
	ConfigDirs: map[string][]string{
		"linux":   {"~/.config/localai"},
		"darwin":  {"~/.config/localai"},
		"windows": {"~/.config/localai"},
	},
}
