package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWritableByOthersFindsAFolderThisUserOwns(t *testing.T) {
	file := filepath.Join(t.TempDir(), "aditd")
	os.WriteFile(file, []byte("x"), 0o755)
	if os.Geteuid() != 0 && writableByOthers(file) == "" {
		t.Error("a file in a folder this (non-root) user owns was not flagged")
	}
	if got := writableByOthers("/usr/bin/true"); got != "" {
		t.Errorf("/usr/bin/true flagged at %s", got)
	}
}

func TestStageCopiesIntoAFolderOfItsOwn(t *testing.T) {
	dir := t.TempDir()
	aditd, tray := filepath.Join(dir, "aditd"), filepath.Join(dir, "adit-tray")
	os.WriteFile(aditd, []byte("daemon"), 0o755)
	os.WriteFile(tray, []byte("icon"), 0o755)
	staged, cleanUp, err := stageCopies(aditd, tray)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"daemon", "icon"} {
		if got, _ := os.ReadFile(staged[i]); string(got) != want {
			t.Errorf("copy %d holds %q", i, got)
		}
	}
	if info, _ := os.Stat(filepath.Dir(staged[0])); info.Mode().Perm() != 0o700 {
		t.Errorf("the folder is %o, want 700", info.Mode().Perm())
	}
	cleanUp()
	if _, err := os.Stat(staged[0]); !os.IsNotExist(err) {
		t.Error("the copies were not removed")
	}
}
