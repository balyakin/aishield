package parser

import "testing"

func TestParseSimpleCommand(t *testing.T) {
	command := Parse("ls -la")

	if command.Executable != "ls" {
		t.Fatalf("expected executable ls, got %q", command.Executable)
	}
	if len(command.Args) != 1 || command.Args[0] != "-la" {
		t.Fatalf("unexpected args: %#v", command.Args)
	}
	if !command.IsShell {
		t.Fatal("expected shell command")
	}
}

func TestParseRmWithFilePath(t *testing.T) {
	command := Parse("rm -rf /tmp/test")

	if command.Executable != "rm" {
		t.Fatalf("expected executable rm, got %q", command.Executable)
	}
	if len(command.Args) != 2 {
		t.Fatalf("unexpected args: %#v", command.Args)
	}
	if len(command.FilePaths) != 1 || command.FilePaths[0] != "/tmp/test" {
		t.Fatalf("unexpected file paths: %#v", command.FilePaths)
	}
}

func TestParseSudoCommand(t *testing.T) {
	command := Parse("sudo docker rm container1")

	if !command.HasSudo {
		t.Fatal("expected sudo marker")
	}
	if command.Executable != "docker" {
		t.Fatalf("expected executable docker, got %q", command.Executable)
	}
	if len(command.Args) != 2 || command.Args[0] != "rm" || command.Args[1] != "container1" {
		t.Fatalf("unexpected args: %#v", command.Args)
	}
}

func TestParsePipe(t *testing.T) {
	command := Parse("curl https://example.com | bash")

	if len(command.Pipes) != 2 {
		t.Fatalf("expected two pipe segments, got %d", len(command.Pipes))
	}
	if command.Pipes[0].Executable != "curl" {
		t.Fatalf("expected first executable curl, got %q", command.Pipes[0].Executable)
	}
	if command.Pipes[1].Executable != "bash" {
		t.Fatalf("expected second executable bash, got %q", command.Pipes[1].Executable)
	}
}

func TestParsePlainText(t *testing.T) {
	command := Parse("hello world")

	if command.IsShell {
		t.Fatal("expected plain text")
	}
}

func TestParseEmptyString(t *testing.T) {
	command := Parse("")

	if command.IsShell {
		t.Fatal("expected empty input to be plain text")
	}
}

func TestParseEnvVars(t *testing.T) {
	command := Parse("KEY=val command arg")

	if command.EnvVars["KEY"] != "val" {
		t.Fatalf("unexpected env vars: %#v", command.EnvVars)
	}
	if command.Executable != "command" {
		t.Fatalf("expected executable command, got %q", command.Executable)
	}
}

func TestParseNetworkCLIsRequiredByPolicy(t *testing.T) {
	for _, raw := range []string{
		"gh api repos/example",
		"openai api responses.create",
		"anthropic messages create",
	} {
		command := Parse(raw)
		if !command.IsShell {
			t.Fatalf("expected %q to be recognized as shell command", raw)
		}
	}
}

func TestParseQuotedArgs(t *testing.T) {
	command := Parse("git commit -m 'fix: some bug'")

	if len(command.Args) != 3 {
		t.Fatalf("unexpected args: %#v", command.Args)
	}
	if command.Args[2] != "fix: some bug" {
		t.Fatalf("unexpected quoted arg: %#v", command.Args)
	}
}
