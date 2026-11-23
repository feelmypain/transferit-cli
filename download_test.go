package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseTransferHandle(t *testing.T) {
	tests := map[string]string{
		"https://transfer.it/t/AbC123_-":           "AbC123_-",
		"http://www.transfer.it/t/xyz789":          "xyz789",
		"https://transfer.it/something/t/Handle42": "Handle42",
		"transfer.it/t/Bare42":                     "Bare42",
		"open https://transfer.it/t/Embedded99":    "Embedded99",
	}
	for input, want := range tests {
		got, err := parseTransferHandle(input)
		if err != nil {
			t.Fatalf("parseTransferHandle(%q) returned error: %v", input, err)
		}
		if got != want {
			t.Fatalf("parseTransferHandle(%q) = %q, want %q", input, got, want)
		}
	}
}

// The bare-host form is dispatched by main() as a download, so the pattern it keys
// on must agree with parseTransferHandle and must not swallow the subcommands.
func TestLinkPatternDispatchAgreesWithParsing(t *testing.T) {
	for _, arg := range []string{"transfer.it/t/Bare42", "https://transfer.it/t/AbC123_-", "www.transfer.it/t/xyz789"} {
		if !linkRE.MatchString(arg) {
			t.Fatalf("%q would be rejected as an unknown command", arg)
		}
		if _, err := parseTransferHandle(arg); err != nil {
			t.Fatalf("parseTransferHandle(%q) = %v", arg, err)
		}
	}
	for _, arg := range []string{"download", "upload", "account", "help", "-h", "--help"} {
		if linkRE.MatchString(arg) {
			t.Fatalf("subcommand %q was matched as a transfer link", arg)
		}
	}
}

func TestParseTransferHandleRejectsOtherHosts(t *testing.T) {
	for _, input := range []string{
		"https://nottransfer.it/t/abc",
		"https://evil-transfer.it/t/abc",
	} {
		if got, err := parseTransferHandle(input); err == nil {
			t.Fatalf("parseTransferHandle(%q) = %q, want error", input, got)
		}
	}
}

func TestVerifyDownloadedFileDetectsSameSizeCorruption(t *testing.T) {
	data := make([]byte, 2*1024*1024+17)
	for i := range data {
		data[i] = byte((i*31 + (i >> 5) + 7) & 0xff)
	}
	ukey := []uint32{0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0x15161718}
	macs := make([][]byte, 0)
	for _, ch := range getChunkSizes(int64(len(data))) {
		_, mac, err := encryptUploadChunk(data[ch.position:ch.position+int64(ch.size)], ukey, ch.position)
		if err != nil {
			t.Fatal(err)
		}
		macs = append(macs, mac)
	}
	fileKey, err := buildFileKey(ukey, macs)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "download.bin")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	node := transferNode{K: b64Encode(wordsToBytes(fileKey)), S: int64(len(data))}
	if err := verifyDownloadedFile(path, node); err != nil {
		t.Fatalf("valid file failed verification: %v", err)
	}

	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyDownloadedFile(path, node); err == nil {
		t.Fatal("same-size corrupted file passed verification")
	}
}

func TestReserveFilePathDisambiguatesCollision(t *testing.T) {
	seen := map[string]reservedPath{}
	dir := t.TempDir()
	dst := filepath.Join(dir, "same.txt")
	first, err := reserveFilePath(seen, dst, "file a/b")
	if err != nil {
		t.Fatal(err)
	}
	if first != dst {
		t.Fatalf("first reservation = %q, want %q", first, dst)
	}
	second, err := reserveFilePath(seen, filepath.Clean(dst), "file a_b")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "same (1).txt"); second != want {
		t.Fatalf("second reservation = %q, want %q", second, want)
	}
	third, err := reserveFilePath(seen, dst, "file a-b")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "same (2).txt"); third != want {
		t.Fatalf("third reservation = %q, want %q", third, want)
	}
}

func TestReserveFolderPathMergesAndBlocksFileConflicts(t *testing.T) {
	root := t.TempDir()
	seen := map[string]reservedPath{}
	dst := filepath.Join(root, "shared")
	if err := reserveFolderPath(seen, dst, "folder a/shared"); err != nil {
		t.Fatal(err)
	}
	// Two remote folders that sanitize to the same local path merge rather than fail;
	// renaming would be unsound because child paths are derived independently.
	if err := reserveFolderPath(seen, dst, "folder b/shared"); err != nil {
		t.Fatalf("folder reservations did not merge: %v", err)
	}
	// A file landing on a reserved directory is still a hard error.
	if _, err := reserveFilePath(seen, dst, "file shared"); err == nil {
		t.Fatal("file was allowed to claim a reserved folder path")
	} else if !strings.Contains(err.Error(), "download path collision") {
		t.Fatalf("collision error = %v", err)
	}
}

func TestReserveFilePathSeparatesPortableCollisions(t *testing.T) {
	root := t.TempDir()
	for _, paths := range [][2]string{
		{"File.txt", "file.txt"},
		{"name", "name. "},
		{"file", "file.part"},
		{"é.txt", "é.txt"},
		{"Straße.txt", "STRASSE.txt"},
	} {
		seen := map[string]reservedPath{}
		first, err := reserveFilePath(seen, filepath.Join(root, paths[0]), "first")
		if err != nil {
			t.Fatal(err)
		}
		second, err := reserveFilePath(seen, filepath.Join(root, paths[1]), "second")
		if err != nil {
			t.Fatal(err)
		}
		// Both nodes must stay downloadable, and neither may share a destination or
		// a .part sidecar with the other on any supported filesystem.
		for _, pair := range [][2]string{
			{first, second},
			{first + ".part", second},
			{first, second + ".part"},
			{first + ".part", second + ".part"},
		} {
			if portableDownloadPathKey(pair[0]) == portableDownloadPathKey(pair[1]) {
				t.Fatalf("%q and %q still collide: %q vs %q", paths[0], paths[1], pair[0], pair[1])
			}
		}
	}
}

func TestResolveDownloadPathContainsRemoteNames(t *testing.T) {
	root := t.TempDir()
	got, err := resolveDownloadPath(root, "folder/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "folder", "file.txt"); got != want {
		t.Fatalf("resolved path = %q, want %q", got, want)
	}
	for _, rel := range []string{"../escape", "folder/../../escape", "/absolute"} {
		if _, err := resolveDownloadPath(root, rel); err == nil {
			t.Fatalf("resolveDownloadPath(%q) succeeded", rel)
		}
	}
}

func TestRejectSymlinkComponents(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := rejectSymlinkComponents(root, filepath.Join(link, "file")); err == nil {
		t.Fatal("symlinked parent was accepted")
	}
}

func TestRejectSymlinkAtGeneratedRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	generatedRoot := filepath.Join(root, "transfer-title")
	if err := os.Symlink(outside, generatedRoot); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := rejectSymlinkComponents(root, generatedRoot); err == nil {
		t.Fatal("symlinked generated root was accepted")
	}
}

func TestRootConfinedFileCreationRejectsEscapingSymlink(t *testing.T) {
	rootPath := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(rootPath, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := root.OpenFile(filepath.Join("escape", "payload"), os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		file.Close()
		t.Fatal("root-confined file creation followed an escaping symlink")
	}
	if _, err := os.Stat(filepath.Join(outside, "payload")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside payload exists or could not be checked: %v", err)
	}
}

func TestBuildNodePathRejectsMalformedParents(t *testing.T) {
	root := &transferNode{H: "root", Name: "root"}
	folder := &transferNode{H: "folder", P: "root", Name: "folder"}
	sub := &transferNode{H: "sub", P: "folder", Name: "sub"}
	file := &transferNode{H: "file", P: "sub", Name: "file.txt"}
	nodes := map[string]*transferNode{"root": root, "folder": folder, "sub": sub, "file": file}
	if got, err := buildNodePath(file, nodes); err != nil || got != "folder/sub/file.txt" {
		t.Fatalf("buildNodePath = %q, %v", got, err)
	}

	file.P = "missing"
	if _, err := buildNodePath(file, nodes); err == nil {
		t.Fatal("missing parent was accepted")
	}
	file.P = "folder"
	folder.P = "file"
	if _, err := buildNodePath(file, nodes); err == nil {
		t.Fatal("parent cycle was accepted")
	}
}

func TestValidateContentRange(t *testing.T) {
	if err := validateContentRange("bytes 5-9/10", 5, 10); err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"", "bytes 4-9/10", "bytes 5-8/10", "bytes 5-9/11"} {
		if err := validateContentRange(header, 5, 10); err == nil {
			t.Fatalf("validateContentRange(%q) succeeded", header)
		}
	}
}

func TestIdleTimeoutReaderStopsStalledHTTPRead(t *testing.T) {
	unblock := make(chan struct{})
	defer close(unblock)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-unblock:
		}
	}))
	defer server.Close()

	reqCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	reader := newIdleTimeoutReader(resp.Body, 20*time.Millisecond, cancel)
	defer reader.Close()

	buf := make([]byte, 16)
	n, err := reader.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("initial read = %q, %v; want ok, nil", buf[:n], err)
	}
	if _, err := reader.Read(buf); !errors.Is(err, errDownloadTransient) || !strings.Contains(err.Error(), "stalled") {
		t.Fatalf("stalled read error = %v, want transient stall error", err)
	}
}

// downloadTestNode publishes data through a fake transfer API and returns the node
// describing it, with transferAPI pointed at the test server for the duration.
func downloadTestNode(t *testing.T, data []byte, handler http.HandlerFunc) transferNode {
	t.Helper()
	ukey := []uint32{0x21222324, 0x25262728, 0x292a2b2c, 0x2d2e2f30, 0x31323334, 0x35363738}
	macs, err := chunkMACs(bytes.NewReader(data), ukey, getChunkSizes(int64(len(data))))
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := buildFileKey(ukey, macs)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	original := transferAPI
	transferAPI = server.URL
	t.Cleanup(func() { transferAPI = original })
	return transferNode{H: "nodehandle", Name: "payload.bin", S: int64(len(data)), K: b64Encode(wordsToBytes(fileKey))}
}

func serveRange(w http.ResponseWriter, r *http.Request, data []byte) {
	start := int64(0)
	if rng := r.Header.Get("Range"); rng != "" {
		if _, err := fmt.Sscanf(rng, "bytes=%d-", &start); err != nil || start < 0 || start > int64(len(data)) {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(data)-1, len(data)))
		w.WriteHeader(http.StatusPartialContent)
	}
	_, _ = w.Write(data[start:])
}

func TestDownloadNodeRetriesTransientFailuresAndResumes(t *testing.T) {
	data := make([]byte, 300000)
	for i := range data {
		data[i] = byte((i*13 + 3) & 0xff)
	}
	var mu sync.Mutex
	attempts := 0
	node := downloadTestNode(t, data, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		attempt := attempts
		mu.Unlock()
		switch attempt {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("busy"))
		case 2:
			// Declare the full length but close early: a truncated body.
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data[:1000])
		default:
			serveRange(w, r, data)
		}
	})

	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := downloadNode(context.Background(), root, "transferhandle", "", node, "payload.bin", "payload.bin"); err != nil {
		t.Fatalf("download did not recover from transient failures: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root.Name(), "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("downloaded bytes do not match the source")
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != 3 {
		t.Fatalf("server saw %d attempts, want 3 (503, truncated, resumed)", attempts)
	}
}

func TestDownloadNodeRestartsWhenResumeIsRejected(t *testing.T) {
	data := make([]byte, 200000)
	for i := range data {
		data[i] = byte((i*7 + 5) & 0xff)
	}
	var mu sync.Mutex
	sawRange := false
	node := downloadTestNode(t, data, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			mu.Lock()
			sawRange = true
			mu.Unlock()
			// A proxy that answers a resume with a bogus range.
			w.Header().Set("Content-Range", "bytes 0-9/10")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(data[:10])
			return
		}
		_, _ = w.Write(data)
	})

	dir := t.TempDir()
	// A stale .part forces the resume path on the first attempt.
	if err := os.WriteFile(filepath.Join(dir, "payload.bin.part"), data[:50000], 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := downloadNode(context.Background(), root, "transferhandle", "", node, "payload.bin", "payload.bin"); err != nil {
		t.Fatalf("download did not recover from a rejected resume: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("downloaded bytes do not match the source")
	}
	mu.Lock()
	defer mu.Unlock()
	if !sawRange {
		t.Fatal("expected the first attempt to try resuming")
	}
}

// Starting with no .part file, a mid-stream disconnect triggers an internal resume;
// if the resumed tail is corrupt, downloadNode must still retry cleanly from byte 0.
func TestDownloadNodeRetriesFromStartAfterCorruptedInternalResume(t *testing.T) {
	data := make([]byte, 200000)
	for i := range data {
		data[i] = byte((i*23 + 11) & 0xff)
	}
	corrupt := append([]byte(nil), data...)
	corrupt[len(corrupt)-1] ^= 0xff

	var mu sync.Mutex
	attempts := 0
	node := downloadTestNode(t, data, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		attempt := attempts
		mu.Unlock()
		switch attempt {
		case 1:
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data[:60000])
		case 2:
			serveRange(w, r, corrupt)
		default:
			_, _ = w.Write(data)
		}
	})

	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := downloadNode(context.Background(), root, "transferhandle", "", node, "payload.bin", "payload.bin"); err != nil {
		t.Fatalf("download did not restart from byte 0 after corrupted internal resume: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root.Name(), "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("downloaded bytes do not match the source")
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3 (truncated, corrupt resume, clean restart)", attempts)
	}
}

func FuzzResolveDownloadPath(f *testing.F) {
	root := f.TempDir()
	for _, seed := range []string{"file.txt", "folder/file.txt", "../escape", "/absolute", ".", ".."} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, rel string) {
		dst, err := resolveDownloadPath(root, rel)
		if err != nil {
			return
		}
		within, err := filepath.Rel(root, dst)
		if err != nil {
			t.Fatal(err)
		}
		if within == ".." || strings.HasPrefix(within, ".."+string(filepath.Separator)) {
			t.Fatalf("resolved path escaped root: rel=%q dst=%q", rel, dst)
		}
	})
}
