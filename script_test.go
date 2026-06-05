package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"net/http"
	"net/http/httptest"
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
	poster := func(_ string, offset int64, encrypted []byte) ([]byte, error) {
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
	poster := func(_ string, offset int64, encrypted []byte) ([]byte, error) {
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

func TestUploadEncryptionRoundTrip(t *testing.T) {
	data := make([]byte, 5*1024*1024+123)
	for i := range data {
		data[i] = byte((i*19 + (i>>8)*7 + 91) & 0xff)
	}
	chunks := getChunkSizes(int64(len(data)))
	ukey := []uint32{0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0x15161718}

	encryptedByOffset := map[int64][]byte{}
	var mu sync.Mutex
	poster := func(_ string, offset int64, encrypted []byte) ([]byte, error) {
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
	block, err := aes.NewCipher(wordsToBytes(attrAESKey(fileKey)))
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
}
