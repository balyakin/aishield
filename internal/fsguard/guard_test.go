package fsguard

import "testing"

func TestBlocksWriteToReadOnlyPath(t *testing.T) {
	guard := NewGuard([]string{"/etc/*"}, nil, nil, "/home/user/project")

	result := guard.Check([]string{"/etc/hosts"}, true)

	if result.Allowed {
		t.Fatal("expected read-only write to be blocked")
	}
}

func TestAllowsReadFromReadOnlyPath(t *testing.T) {
	guard := NewGuard([]string{"/etc/*"}, nil, nil, "/home/user/project")

	result := guard.Check([]string{"/etc/hosts"}, false)

	if !result.Allowed {
		t.Fatalf("expected read to be allowed: %s", result.Reason)
	}
}

func TestBlocksBlockedPath(t *testing.T) {
	guard := NewGuard(nil, []string{"/System/*"}, nil, "/home/user/project")

	result := guard.Check([]string{"/System/Library"}, false)

	if result.Allowed {
		t.Fatal("expected blocked path to be blocked")
	}
}

func TestAllowsWorkDirWrite(t *testing.T) {
	guard := NewGuard([]string{"/etc/*"}, []string{"/System/*"}, nil, "/home/user/project")

	result := guard.Check([]string{"/home/user/project/file.go"}, true)

	if !result.Allowed {
		t.Fatalf("expected workdir write to be allowed: %s", result.Reason)
	}
}

func TestBlocksSecretFile(t *testing.T) {
	guard := NewGuard(nil, nil, []string{".env"}, "/home/user/project")

	result := guard.Check([]string{"/home/user/project/.env"}, false)

	if result.Allowed {
		t.Fatal("expected secret file to be blocked")
	}
}
