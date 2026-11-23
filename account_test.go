package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAccountSessionOmitsMasterKey(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HOME", base)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
	t.Setenv("AppData", filepath.Join(base, "config"))
	if err := saveAccountSession("User@Example.com", "", session{sid: "session", masterKey: []uint32{1, 2, 3, 4}}); err != nil {
		t.Fatal(err)
	}
	path, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("master_key")) {
		t.Fatalf("config persisted master key: %s", data)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.PathSeparator != '\\' && st.Mode().Perm() != 0600 {
		t.Fatalf("config mode = %v, want 0600", st.Mode().Perm())
	}
}

func TestPasswordToPersist(t *testing.T) {
	saved := savedConfig{Account: savedAccount{Email: "user@example.com", Password: "stored"}}
	none := savedConfig{Account: savedAccount{Email: "user@example.com"}}

	tests := []struct {
		name               string
		cfg                savedConfig
		email              string
		savePassword       bool
		passwordFromConfig bool
		want               string
	}{
		{"explicit opt-in", none, "user@example.com", true, false, "fresh"},
		{"no opt-in and nothing stored", none, "user@example.com", false, false, ""},
		{"reused stored password", saved, "user@example.com", false, true, "fresh"},
		{"re-login keeps an existing saved password", saved, "USER@Example.com ", false, false, "fresh"},
		{"switching accounts drops it", saved, "other@example.com", false, false, ""},
	}
	for _, tt := range tests {
		got := passwordToPersist(tt.cfg, tt.email, "fresh", tt.savePassword, tt.passwordFromConfig)
		if got != tt.want {
			t.Fatalf("%s: passwordToPersist = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestRunAccountLoginRejectsCorruptConfig(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HOME", base)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
	t.Setenv("AppData", filepath.Join(base, "config"))

	path, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runAccountLogin(context.Background(), []string{"--email", "user@example.com", "--password", "pw"}); err == nil {
		t.Fatal("runAccountLogin ignored a corrupt config.json")
	}
}
