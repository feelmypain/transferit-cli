package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

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

	completion, macs, err := uploadChunks(context.Background(), bytes.NewReader(data), "https://upload.example", ukey, chunks, int64(len(data)), 4, poster)
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

	completion, _, err := uploadChunks(context.Background(), bytes.NewReader(data), "https://upload.example", ukey, chunks, int64(len(data)), 1, poster)
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

	completion, _, err := uploadChunks(context.Background(), bytes.NewReader(data), "https://upload.example", ukey, chunks, int64(len(data)), 1, poster)
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

	if _, _, err := uploadChunks(context.Background(), bytes.NewReader(data), "https://upload.example", ukey, chunks, int64(len(data)), workers, poster); err == nil {
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

	completion, macs, err := uploadChunks(context.Background(), bytes.NewReader(data), "https://upload.example", ukey, chunks, int64(len(data)), 4, poster)
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

func TestSetTransferRecipientAlwaysIncludesScheduleField(t *testing.T) {
	tests := []struct {
		name     string
		schedule int64
		wantS    float64
	}{
		{"unscheduled sends s=0", 0, 0},
		{"negative schedule clamps to s=0", -5, 0},
		{"scheduled sends timestamp", 1893456000, 1893456000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer r.Body.Close()
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Errorf("decode request body: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("[0]"))
			}))
			defer server.Close()

			if err := setTransferRecipient(context.Background(), &apiClient{base: server.URL}, "xh123", "recipient@example.com", tt.schedule); err != nil {
				t.Fatalf("setTransferRecipient returned error: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("sent %d commands, want 1", len(got))
			}
			req := got[0]
			if req["a"] != "xr" || req["xh"] != "xh123" || req["e"] != "recipient@example.com" {
				t.Fatalf("unexpected xr payload: %#v", req)
			}
			rawS, ok := req["s"]
			if !ok {
				t.Fatalf("xr payload omitted required 's' field: %#v", req)
			}
			if rawS != tt.wantS {
				t.Fatalf("xr payload s = %#v, want %v", rawS, tt.wantS)
			}
		})
	}
}
