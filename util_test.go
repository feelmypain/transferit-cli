package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSafeName(t *testing.T) {
	got := safeName("a/b\\c\x00d")
	want := "a_b_cd"
	if got != want {
		t.Fatalf("safeName = %q, want %q", got, want)
	}
	if filepath.Separator == '/' && safeName(" ") != "unnamed" {
		t.Fatal("blank names should be mapped to unnamed")
	}
	if safeName(".") == "." || safeName("..") == ".." {
		t.Fatal("dot path components must be rewritten")
	}
	for _, name := range []string{
		"CON", "con.txt", "CON .txt", "CONIN$", "CONOUT$", "LPT1", "COM1 .log", "COM¹", "LPT²",
		"LONGFI~1.TXT", "éééé~1.TXT", "name. ", "foo:bar", `bad<name>|?*"`,
	} {
		got := safeName(name)
		if got == name || strings.HasSuffix(got, ".") || strings.HasSuffix(got, " ") {
			t.Fatalf("unsafe portable name %q was mapped to %q", name, got)
		}
	}
}

func TestPromptsShareOneStdinReader(t *testing.T) {
	original := stdinReader
	t.Cleanup(func() { stdinReader = original })
	stdinReader = bufio.NewReader(strings.NewReader("user@example.com\nhunter2\n"))

	email, err := promptLine("email: ")
	if err != nil {
		t.Fatal(err)
	}
	if email != "user@example.com" {
		t.Fatalf("email = %q", email)
	}
	// A per-prompt bufio.Reader would have swallowed this in the first read-ahead.
	password, err := promptSecret(context.Background(), "password: ")
	if err != nil {
		t.Fatal(err)
	}
	if password != "hunter2" {
		t.Fatalf("password = %q, want the second piped line", password)
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	return len(p) - 1, nil
}

func TestCopyWithProgressRejectsShortWrite(t *testing.T) {
	if err := copyWithProgress(shortWriter{}, strings.NewReader("data"), 0, 4); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("copy error = %v, want io.ErrShortWrite", err)
	}
}

func TestReorderFlagsFirst(t *testing.T) {
	fs := flag.NewFlagSet("upload", flag.ContinueOnError)
	title := fs.String("title", "", "")
	account := fs.Bool("account", false, "")
	expire := fs.Int("expire", 90, "")

	args := []string{"./file1.bin", "--title", "My Title", "--account", "./file2.bin", "--expire=7", "--", "-literal.bin"}
	if err := fs.Parse(reorderFlagsFirst(fs, args)); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if *title != "My Title" || !*account || *expire != 7 {
		t.Fatalf("flags = title:%q account:%t expire:%d", *title, *account, *expire)
	}
	wantPos := []string{"./file1.bin", "./file2.bin", "-literal.bin"}
	if !slices.Equal(fs.Args(), wantPos) {
		t.Fatalf("positionals = %v, want %v", fs.Args(), wantPos)
	}
}
