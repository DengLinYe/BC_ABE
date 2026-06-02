package pathutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"bc_abe/utils/pathutil"
)

func TestRootFromSubModuleDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "bc_abe")
	sub := filepath.Join(root, "auth_admin")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module bc_abe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "go.mod"), []byte("module bc_abe_aa\n\nrequire bc_abe => ../\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Chdir(sub)
	t.Setenv("BC_ABE_ROOT", root)

	got := pathutil.Root()
	if got != root {
		t.Fatalf("Root() = %q, want %q", got, root)
	}

	networkDir := pathutil.Abs("./pkg/fabric/test-network")
	want := filepath.Join(root, "pkg/fabric/test-network")
	if networkDir != want {
		t.Fatalf("Abs(network) = %q, want %q", networkDir, want)
	}
}
