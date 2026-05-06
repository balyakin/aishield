package policy

func StrictRules() []Rule {
	return []Rule{
		{
			Name:        "allow-read-commands",
			Description: "Allow common read-only commands",
			Decision:    Allow,
			Severity:    SeverityInfo,
			Match: MatchCriteria{
				Executables: []string{
					"ls", "cat", "head", "tail", "less", "more", "find", "grep", "awk", "sed", "wc", "sort",
					"uniq", "diff", "file", "stat", "pwd", "echo", "printf", "date", "which", "whereis", "man",
				},
			},
		},
		{
			Name:        "allow-git-read",
			Description: "Allow read-only git commands",
			Decision:    Allow,
			Severity:    SeverityInfo,
			Match: MatchCriteria{
				Executables: []string{"git"},
				ArgsContain: []string{
					"status", "log", "diff", "show", "branch", "remote", "tag", "stash list",
				},
			},
		},
		{
			Name:        "warn-git-write",
			Description: "Warn before git history or remote changes",
			Decision:    Warn,
			Severity:    SeverityWarn,
			Match: MatchCriteria{
				Executables: []string{"git"},
				ArgsContain: []string{"push", "commit", "merge", "rebase", "reset", "checkout", "pull"},
			},
		},
		{
			Name:        "allow-build-tools",
			Description: "Allow common build tools",
			Decision:    Allow,
			Severity:    SeverityInfo,
			Match: MatchCriteria{
				Executables: []string{
					"go", "cargo", "npm", "yarn", "pnpm", "pip", "make", "cmake", "python", "node", "ruby",
					"rustc", "gcc", "javac",
				},
			},
		},
		{
			Name:        "warn-package-install",
			Description: "Warn before package installation",
			Decision:    Warn,
			Severity:    SeverityWarn,
			Match: MatchCriteria{
				Executables: []string{"npm", "yarn", "pnpm", "pip", "cargo", "go", "brew", "apt", "apt-get"},
				ArgsContain: []string{"install", "add", "get"},
			},
		},
		{
			Name:        "block-dangerous-rm",
			Description: "Recursive force delete detected",
			Decision:    Block,
			Severity:    SeverityCritical,
			Match: MatchCriteria{
				Executables: []string{"rm"},
				ArgsContain: []string{"-rf", "-fr", "--recursive --force"},
			},
		},
		{
			Name:        "block-pipe-to-shell",
			Description: "Piping network content to shell is blocked",
			Decision:    Block,
			Severity:    SeverityCritical,
			Match: MatchCriteria{
				RawRegex: []string{`\|\s*(bash|sh|zsh)`, `curl.*\|`, `wget.*\|`},
			},
		},
		{
			Name:        "block-sudo",
			Description: "sudo is blocked in strict preset",
			Decision:    Block,
			Severity:    SeverityCritical,
			Match: MatchCriteria{
				Executables: []string{"sudo"},
			},
		},
		{
			Name:        "block-network-tools",
			Description: "Network tools are blocked in strict preset",
			Decision:    Block,
			Severity:    SeverityCritical,
			Match: MatchCriteria{
				Executables: []string{"curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "rsync", "ftp", "sftp", "telnet"},
			},
		},
		{
			Name:        "block-docker-destructive",
			Description: "Destructive Docker operation detected",
			Decision:    Block,
			Severity:    SeverityCritical,
			Match: MatchCriteria{
				Executables: []string{"docker"},
				ArgsContain: []string{"rm", "rmi", "prune", "system prune", "kill", "stop"},
			},
		},
		{
			Name:        "block-destructive-infra",
			Description: "Destructive infrastructure operation detected",
			Decision:    Block,
			Severity:    SeverityCritical,
			Match: MatchCriteria{
				Executables: []string{"terraform", "kubectl", "aws", "gcloud", "az"},
				ArgsContain: []string{"destroy", "delete", "remove", "drop", "terminate", "deregister"},
			},
		},
	}
}

func StandardRules() []Rule {
	return []Rule{
		{
			Name:        "block-pipe-to-shell",
			Description: "Piping network content to shell is blocked",
			Decision:    Block,
			Severity:    SeverityCritical,
			Match: MatchCriteria{
				RawRegex: []string{`\|\s*(bash|sh|zsh)`, `curl.*\|.*sh`, `wget.*\|.*sh`},
			},
		},
		{
			Name:        "block-dangerous-rm",
			Description: "Recursive force delete detected",
			Decision:    Block,
			Severity:    SeverityCritical,
			Match: MatchCriteria{
				Executables: []string{"rm"},
				ArgsRegex:   []string{`-[a-z]*r[a-z]*f|--recursive.*--force|--force.*--recursive`},
			},
		},
		{
			Name:        "block-destructive-infra",
			Description: "Destructive infrastructure operation detected",
			Decision:    Block,
			Severity:    SeverityCritical,
			Match: MatchCriteria{
				Executables: []string{"terraform", "kubectl", "aws", "gcloud", "az", "railway"},
				ArgsContain: []string{"destroy", "delete", "remove", "drop", "terminate"},
			},
		},
		{
			Name:        "warn-sudo",
			Description: "sudo requires confirmation",
			Decision:    Warn,
			Severity:    SeverityWarn,
			Match: MatchCriteria{
				Executables: []string{"sudo"},
			},
		},
		{
			Name:        "warn-network-requests",
			Description: "Outbound network request detected",
			Decision:    Warn,
			Severity:    SeverityWarn,
			Match: MatchCriteria{
				Executables: []string{"curl", "wget"},
			},
		},
		{
			Name:        "warn-docker-destructive",
			Description: "Destructive Docker operation detected",
			Decision:    Warn,
			Severity:    SeverityWarn,
			Match: MatchCriteria{
				Executables: []string{"docker"},
				ArgsContain: []string{"rm", "rmi", "prune", "kill"},
			},
		},
		{
			Name:        "warn-git-push",
			Description: "Git push requires confirmation",
			Decision:    Warn,
			Severity:    SeverityWarn,
			Match: MatchCriteria{
				Executables: []string{"git"},
				ArgsContain: []string{"push", "push --force", "push -f"},
			},
		},
		{
			Name:        "warn-chmod-777",
			Description: "chmod 777 requires confirmation",
			Decision:    Warn,
			Severity:    SeverityWarn,
			Match: MatchCriteria{
				Executables: []string{"chmod"},
				ArgsContain: []string{"777"},
			},
		},
		{
			Name:        "warn-dd",
			Description: "dd requires confirmation",
			Decision:    Warn,
			Severity:    SeverityWarn,
			Match: MatchCriteria{
				Executables: []string{"dd"},
			},
		},
		{
			Name:        "block-system-paths",
			Description: "System paths are protected",
			Decision:    Block,
			Severity:    SeverityCritical,
			Match: MatchCriteria{
				FilePaths: []PathRule{
					{Pattern: "/etc/**", Action: "write"},
					{Pattern: "/System/**", Action: "any"},
					{Pattern: "/boot/**", Action: "any"},
				},
			},
		},
		{
			Name:        "block-secret-files",
			Description: "Secret file access is blocked",
			Decision:    Block,
			Severity:    SeverityCritical,
			Match: MatchCriteria{
				FilePaths: []PathRule{
					{Pattern: ".env", Action: "any"},
					{Pattern: ".env.*", Action: "any"},
					{Pattern: "*.pem", Action: "any"},
					{Pattern: "*.key", Action: "any"},
					{Pattern: "id_rsa", Action: "any"},
					{Pattern: "id_ed25519", Action: "any"},
					{Pattern: "~/.ssh/**", Action: "any"},
					{Pattern: "~/.aws/credentials", Action: "any"},
					{Pattern: "~/.config/gcloud/**", Action: "any"},
					{Pattern: "~/.docker/config.json", Action: "any"},
					{Pattern: ".npmrc", Action: "any"},
					{Pattern: ".pypirc", Action: "any"},
				},
			},
		},
	}
}

func PermissiveRules() []Rule {
	return []Rule{
		{
			Name:        "block-pipe-to-shell",
			Description: "Piping network content to shell is blocked",
			Decision:    Block,
			Severity:    SeverityCritical,
			Match: MatchCriteria{
				RawRegex: []string{`curl.*\|\s*(bash|sh|zsh)`, `wget.*\|\s*(bash|sh|zsh)`},
			},
		},
		{
			Name:        "warn-dangerous-rm",
			Description: "Recursive force delete requires confirmation",
			Decision:    Warn,
			Severity:    SeverityWarn,
			Match: MatchCriteria{
				Executables: []string{"rm"},
				ArgsRegex:   []string{`-[a-z]*r[a-z]*f`},
			},
		},
		{
			Name:        "warn-destructive-infra",
			Description: "Destructive infrastructure operation requires confirmation",
			Decision:    Warn,
			Severity:    SeverityWarn,
			Match: MatchCriteria{
				Executables: []string{"terraform", "kubectl", "aws"},
				ArgsContain: []string{"destroy", "delete", "drop"},
			},
		},
	}
}
