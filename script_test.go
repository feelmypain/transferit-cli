package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
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

func TestGetChunkSizesBoundaries(t *testing.T) {
	tests := []struct {
		size int64
		want []chunkSize
	}{
		{0, nil},
		{1, []chunkSize{{position: 0, size: 1}}},
		{131072, []chunkSize{{position: 0, size: 131072}}},
		{131073, []chunkSize{{position: 0, size: 131072}, {position: 131072, size: 1}}},
		{393216, []chunkSize{{position: 0, size: 131072}, {position: 131072, size: 262144}}},
	}
	for _, tt := range tests {
		got := getChunkSizes(tt.size)
		if !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("getChunkSizes(%d) = %+v, want %+v", tt.size, got, tt.want)
		}
	}
}

func TestAttributeRoundTrip(t *testing.T) {
	folderKey := []uint32{0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10}
	attr, err := encryptAttr(map[string]any{"n": "folder-name"}, folderKey)
	if err != nil {
		t.Fatal(err)
	}
	name, err := decryptNodeName(attr, b64Encode(wordsToBytes(folderKey)))
	if err != nil {
		t.Fatal(err)
	}
	if name != "folder-name" {
		t.Fatalf("folder attr name = %q", name)
	}

	fileKey := []uint32{0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20, 0x21222324, 0x25262728, 0x292a2b2c, 0x2d2e2f30}
	attr, err = encryptAttr(map[string]any{"n": "file-name.bin"}, fileKey)
	if err != nil {
		t.Fatal(err)
	}
	name, err = decryptNodeName(attr, b64Encode(wordsToBytes(fileKey)))
	if err != nil {
		t.Fatal(err)
	}
	if name != "file-name.bin" {
		t.Fatalf("file attr name = %q", name)
	}
}

func TestUploadChunksKeepsFinalChunkLast(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 3*1024*1024)
	chunks := getChunkSizes(int64(len(data)))
	if len(chunks) < 3 {
		t.Fatalf("expected multiple chunks, got %d", len(chunks))
	}
	finalOffset := chunks[len(chunks)-1].position
	ukey := []uint32{0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0x15161718}

	var mu sync.Mutex
	var offsets []int64
	poster := func(_ context.Context, _ string, offset int64, encrypted []byte) ([]byte, error) {
		time.Sleep(time.Millisecond)
		mu.Lock()
		offsets = append(offsets, offset)
		mu.Unlock()
		if offset == finalOffset {
			return []byte("completion-handle"), nil
		}
		return nil, nil
	}

	completion, macs, err := uploadChunks(bytes.NewReader(data), "https://upload.example", ukey, chunks, int64(len(data)), 4, poster)
	if err != nil {
		t.Fatal(err)
	}
	if completion != "completion-handle" {
		t.Fatalf("completion = %q", completion)
	}
	if len(macs) != len(chunks) {
		t.Fatalf("mac count = %d, want %d", len(macs), len(chunks))
	}
	for i, mac := range macs {
		if len(mac) != 16 {
			t.Fatalf("mac %d length = %d, want 16", i, len(mac))
		}
	}

	mu.Lock()
	gotCount := len(offsets)
	gotLast := offsets[len(offsets)-1]
	mu.Unlock()
	if gotCount != len(chunks) {
		t.Fatalf("posted %d chunks, want %d", gotCount, len(chunks))
	}
	if gotLast != finalOffset {
		t.Fatalf("last posted offset = %d, want final offset %d", gotLast, finalOffset)
	}
}

func TestUploadChunksSequentialWorkerPostsEveryChunk(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 3*1024*1024)
	chunks := getChunkSizes(int64(len(data)))
	ukey := []uint32{0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0x15161718}

	var offsets []int64
	poster := func(_ context.Context, _ string, offset int64, encrypted []byte) ([]byte, error) {
		offsets = append(offsets, offset)
		if offset == chunks[len(chunks)-1].position {
			return []byte("completion-handle"), nil
		}
		return nil, nil
	}

	completion, _, err := uploadChunks(bytes.NewReader(data), "https://upload.example", ukey, chunks, int64(len(data)), 1, poster)
	if err != nil {
		t.Fatal(err)
	}
	if completion != "completion-handle" {
		t.Fatalf("completion = %q", completion)
	}
	if len(offsets) != len(chunks) {
		t.Fatalf("posted %d chunks, want %d", len(offsets), len(chunks))
	}
	for i, ch := range chunks {
		if offsets[i] != ch.position {
			t.Fatalf("posted offset %d = %d, want %d", i, offsets[i], ch.position)
		}
	}
}

func TestUploadChunksUsesOnlyFinalCompletionResponse(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 512*1024)
	chunks := getChunkSizes(int64(len(data)))
	ukey := []uint32{0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0x15161718}
	poster := func(_ context.Context, _ string, offset int64, _ []byte) ([]byte, error) {
		if offset == chunks[len(chunks)-1].position {
			return nil, nil
		}
		return []byte("intermediate-response"), nil
	}

	completion, _, err := uploadChunks(bytes.NewReader(data), "https://upload.example", ukey, chunks, int64(len(data)), 1, poster)
	if err != nil {
		t.Fatal(err)
	}
	if completion != "" {
		t.Fatalf("completion = %q, want empty final response", completion)
	}
}

func TestUploadChunksStopsWorkersAfterFailure(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 8*1024*1024)
	chunks := getChunkSizes(int64(len(data)))
	ukey := []uint32{0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0x15161718}
	const workers = 4
	var mu sync.Mutex
	posted := 0
	poster := func(ctx context.Context, _ string, _ int64, _ []byte) ([]byte, error) {
		mu.Lock()
		posted++
		call := posted
		mu.Unlock()
		if call == 1 {
			return nil, errors.New("permanent failure")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}

	if _, _, err := uploadChunks(bytes.NewReader(data), "https://upload.example", ukey, chunks, int64(len(data)), workers, poster); err == nil {
		t.Fatal("upload succeeded despite permanent chunk failure")
	}
	mu.Lock()
	defer mu.Unlock()
	if posted > workers {
		t.Fatalf("posted %d chunks after failure with %d workers", posted, workers)
	}
}

func TestUploadEncryptionRoundTrip(t *testing.T) {
	data := make([]byte, 5*1024*1024+123)
	for i := range data {
		data[i] = byte((i*19 + (i>>8)*7 + 91) & 0xff)
	}
	chunks := getChunkSizes(int64(len(data)))
	ukey := []uint32{0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0x15161718}

	encryptedByOffset := map[int64][]byte{}
	var mu sync.Mutex
	poster := func(_ context.Context, _ string, offset int64, encrypted []byte) ([]byte, error) {
		mu.Lock()
		encryptedByOffset[offset] = append([]byte(nil), encrypted...)
		mu.Unlock()
		if offset == chunks[len(chunks)-1].position {
			return []byte("completion-handle"), nil
		}
		return nil, nil
	}

	completion, macs, err := uploadChunks(bytes.NewReader(data), "https://upload.example", ukey, chunks, int64(len(data)), 4, poster)
	if err != nil {
		t.Fatal(err)
	}
	if completion != "completion-handle" {
		t.Fatalf("completion = %q", completion)
	}
	fileKey, err := buildFileKey(ukey, macs)
	if err != nil {
		t.Fatal(err)
	}

	var decrypted []byte
	for _, ch := range chunks {
		mu.Lock()
		encrypted, ok := encryptedByOffset[ch.position]
		mu.Unlock()
		if !ok {
			t.Fatalf("missing encrypted chunk at offset %d", ch.position)
		}
		plain, err := decryptUploadedChunkForTest(fileKey, encrypted, ch.position)
		if err != nil {
			t.Fatal(err)
		}
		decrypted = append(decrypted, plain...)
	}
	if !bytes.Equal(decrypted, data) {
		t.Fatal("decrypted upload bytes do not match original data")
	}
}

func decryptUploadedChunkForTest(fileKey []uint32, encrypted []byte, offset int64) ([]byte, error) {
	aesKey, err := attrAESKey(fileKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(wordsToBytes(aesKey))
	if err != nil {
		return nil, err
	}
	ctrWords := []uint32{fileKey[4], fileKey[5], uint32(uint64(offset) / 0x1000000000), uint32(offset / 16)}
	plain := append([]byte(nil), encrypted...)
	cipher.NewCTR(block, wordsToBytes(ctrWords)).XORKeyStream(plain, plain)
	return plain, nil
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

func TestReserveDownloadPathDetectsCollision(t *testing.T) {
	seen := map[string]string{}
	dst := filepath.Join(t.TempDir(), "same")
	if err := reserveDownloadPath(seen, dst, "file a/b"); err != nil {
		t.Fatal(err)
	}
	err := reserveDownloadPath(seen, filepath.Clean(dst), "file a_b")
	if err == nil {
		t.Fatal("expected collision")
	}
	if !strings.Contains(err.Error(), "download path collision") {
		t.Fatalf("collision error = %v", err)
	}
}

func TestReserveDownloadPathDetectsPortableCollisions(t *testing.T) {
	root := t.TempDir()
	for _, paths := range [][2]string{
		{"File.txt", "file.txt"},
		{"name", "name. "},
		{"file", "file.part"},
		{"é.txt", "é.txt"},
		{"Straße.txt", "STRASSE.txt"},
	} {
		seen := map[string]string{}
		first := filepath.Join(root, paths[0])
		second := filepath.Join(root, paths[1])
		if err := reserveDownloadPath(seen, first, "first"); err != nil {
			t.Fatal(err)
		}
		if paths[1] == "file.part" {
			first = filepath.Join(root, "file") + ".part"
			seen = map[string]string{}
			if err := reserveDownloadPath(seen, first, "partial"); err != nil {
				t.Fatal(err)
			}
		}
		if err := reserveDownloadPath(seen, second, "second"); err == nil {
			t.Fatalf("portable collision %q and %q was accepted", paths[0], paths[1])
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
	file := &transferNode{H: "file", P: "folder", Name: "file.txt"}
	nodes := map[string]*transferNode{"root": root, "folder": folder, "file": file}
	if got, err := buildNodePath(file, nodes); err != nil || got != "folder/file.txt" {
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

func TestMalformedCryptoBlocksReturnErrors(t *testing.T) {
	for _, words := range []int{0, 1, 3, 5, 7, 9} {
		if _, err := attrAESKey(make([]uint32, words)); err == nil {
			t.Fatalf("attrAESKey accepted %d words", words)
		}
	}
	if _, err := decryptWords(make([]uint32, 4), make([]uint32, 3)); err == nil {
		t.Fatal("decryptWords accepted an incomplete AES block")
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

func TestReadBoundedResponse(t *testing.T) {
	if got, err := readBoundedResponse(strings.NewReader("1234"), 4); err != nil || string(got) != "1234" {
		t.Fatalf("bounded response = %q, %v", got, err)
	}
	if _, err := readBoundedResponse(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("oversized response was accepted")
	}
}

type delayedReader struct {
	delay time.Duration
}

func (r delayedReader) Read([]byte) (int, error) {
	time.Sleep(r.delay)
	return 0, io.EOF
}

func TestIdleTimeoutReaderStopsStalledRead(t *testing.T) {
	reader := idleTimeoutReader{reader: delayedReader{delay: 25 * time.Millisecond}, timeout: time.Millisecond}
	if _, err := reader.Read(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), "stalled") {
		t.Fatalf("idle read error = %v", err)
	}
}

func TestSanitizeHTTPErrorRedactsSecrets(t *testing.T) {
	u, err := url.Parse("https://example.test/cs?sid=session-secret&pw=password-secret&x=public")
	if err != nil {
		t.Fatal(err)
	}
	got := sanitizeHTTPError(errors.New("request failed: "+u.String()), u).Error()
	for _, secret := range []string{"session-secret", "password-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("sanitized error leaks %q: %s", secret, got)
		}
	}
	if strings.Contains(got, "/cs") {
		t.Fatalf("sanitized error leaks request path: %s", got)
	}
}

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

func TestCollectUploadItemsRejectsTopLevelSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := collectUploadItems([]string{link}); err == nil {
		t.Fatal("top-level symlink was accepted")
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

func TestDeriveMegaV1LoginStable(t *testing.T) {
	key, userHash, err := deriveMegaV1Login("User@Example.COM", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if got := b64Encode(wordsToBytes(key)); got != "V9l474LpnqUKsABF6GFNew" {
		t.Fatalf("v1 password key = %q", got)
	}
	if userHash != "sSgbS6ks0bE" {
		t.Fatalf("v1 user hash = %q", userHash)
	}
}

func TestDeriveMegaV2LoginStable(t *testing.T) {
	key, userHash, err := deriveMegaV2Login("hunter2hunter2", b64Encode([]byte("0123456789abcdef")))
	if err != nil {
		t.Fatal(err)
	}
	if got := b64Encode(wordsToBytes(key)); got != "Bj_WykjLEC8Xqx_hC2mgvw" {
		t.Fatalf("v2 password key = %q", got)
	}
	if userHash != "dcotppAiMSUMwRUzgQM_4A" {
		t.Fatalf("v2 user hash = %q", userHash)
	}
}

func TestDeriveTransferPasswordStable(t *testing.T) {
	got, err := deriveTransferPassword("MTIzNDU2Nzg5", "secret")
	if err != nil {
		t.Fatal(err)
	}
	want := "aqkBRcA5d8Dw92o_TB8i8VhrkypZy89IRBGYHHk2yCM"
	if got != want {
		t.Fatalf("deriveTransferPassword = %q, want %q", got, want)
	}
}

func TestGenerateHashcashTokenSatisfiesThreshold(t *testing.T) {
	token := bytes.Repeat([]byte{0xa7}, 48)
	// easiness 255 -> threshold ~half the uint32 space, so the search ends quickly
	challenge := "1:255:1700000000:" + b64Encode(token)
	solution, err := generateHashcashToken(challenge)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(solution, ":")
	if len(parts) != 3 || parts[0] != "1" || parts[1] != b64Encode(token) {
		t.Fatalf("solution format = %q", solution)
	}
	prefix, err := b64Decode(parts[2])
	if err != nil || len(prefix) != 4 {
		t.Fatalf("solution prefix = %q (err %v)", parts[2], err)
	}
	buffer := make([]byte, 4+262144*48)
	copy(buffer, prefix)
	for i := 0; i < 262144; i++ {
		copy(buffer[4+i*48:], token)
	}
	sum := sha256.Sum256(buffer)
	hashPrefix := binary.BigEndian.Uint32(sum[:4])
	threshold := uint64(((255&63)<<1)+1) << uint((255>>6)*7+3)
	if uint64(hashPrefix) > threshold {
		t.Fatalf("solution hash prefix %d exceeds threshold %d", hashPrefix, threshold)
	}
}

func TestNegativeAPICodeParsing(t *testing.T) {
	if code, ok := negativeAPICode([]byte("-3")); !ok || code != -3 {
		t.Fatalf("negativeAPICode(-3) = %d, %t; want -3, true", code, ok)
	}
	if _, ok := negativeAPICode([]byte("-2giAbbOn7bc_yDzXEg2jCPqHIRHODZ_X1KQ")); ok {
		t.Fatal("URL-safe upload completion handles starting with '-' must not be treated as API errors")
	}
	if _, ok := negativeAPICode([]byte(" -15\n")); !ok {
		t.Fatal("negativeAPICode should accept whitespace around negative integer errors")
	}
}

func TestFirstNegativeArrayCode(t *testing.T) {
	if code, ok := firstNegativeArrayCode([]byte("[-15]")); !ok || code != -15 {
		t.Fatalf("firstNegativeArrayCode([-15]) = %d, %t; want -15, true", code, ok)
	}
	if _, ok := firstNegativeArrayCode([]byte(`["-2giAbbOn7bc_yDzXEg2jCPqHIRHODZ_X1KQ"]`)); ok {
		t.Fatal("completion-like strings inside arrays must not be treated as API errors")
	}
}

func TestAPICallRetriesNegativeArrayCode(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		if attempts == 1 {
			_, _ = w.Write([]byte("[-3]"))
			return
		}
		_, _ = w.Write([]byte(`[{"ok":true}]`))
	}))
	defer server.Close()

	var out []struct {
		OK bool `json:"ok"`
	}
	err := (&apiClient{base: server.URL}).call([]map[string]any{{"a": "t"}}, nil, &out)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if len(out) != 1 || !out[0].OK {
		t.Fatalf("out = %+v", out)
	}
}

func TestAPICallReturnsNegativeArrayCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[-15]"))
	}))
	defer server.Close()

	err := (&apiClient{base: server.URL}).call([]map[string]any{{"a": "t"}}, nil, nil)
	var apiErr apiError
	if !errors.As(err, &apiErr) || apiErr.Code != -15 {
		t.Fatalf("err = %v, want apiError -15", err)
	}
}

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

func FuzzDecryptNodeNameDoesNotPanic(f *testing.F) {
	f.Add([]byte("not-an-aes-block"), []byte("short-key"))
	f.Add(make([]byte, aes.BlockSize), make([]byte, aes.BlockSize))
	f.Fuzz(func(t *testing.T, attr, key []byte) {
		_, _ = decryptNodeName(b64Encode(attr), b64Encode(key))
	})
}
