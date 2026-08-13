package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPasswordList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.txt")
	content := "password123\n# comment\nletmein\n\nadmin\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	passwords, err := loadPasswordList(path)
	if err != nil {
		t.Fatalf("loadPasswordList error: %v", err)
	}
	if len(passwords) != 3 {
		t.Fatalf("passwords = %d, want 3", len(passwords))
	}
	if passwords[0] != "password123" || passwords[1] != "letmein" || passwords[2] != "admin" {
		t.Errorf("passwords = %v", passwords)
	}
}

func TestLoadPasswordList_Missing(t *testing.T) {
	if _, err := loadPasswordList("/nonexistent/file.txt"); err == nil {
		t.Error("expected error for missing file")
	}
}
