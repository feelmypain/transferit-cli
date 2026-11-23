package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"slices"
	"strings"
	"testing"
)

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

func TestZeroLengthFileMetaMACMatchesMEGA(t *testing.T) {
	ukey := []uint32{0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0x15161718}
	// MEGA condenses no chunk MACs at all for an empty file.
	fileKey, err := buildFileKey(ukey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fileKey[6] != 0 || fileKey[7] != 0 {
		t.Fatalf("empty-file meta-MAC = %08x %08x, want 0 0", fileKey[6], fileKey[7])
	}
	computed, err := computeFileKeyFromReader(bytes.NewReader(nil), fileKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(computed, fileKey) {
		t.Fatalf("zero-length file failed its own verification: %v vs %v", computed, fileKey)
	}
}

func TestChunkMACsMatchEncryptUploadChunk(t *testing.T) {
	ukey := []uint32{0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0x15161718}
	for _, size := range []int{1, 15, 16, 17, 131072, 131073, 393217, 1048576, 3*1024*1024 + 5} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte((i*37 + 11) & 0xff)
		}
		chunks := getChunkSizes(int64(size))
		want := make([][]byte, 0, len(chunks))
		for _, ch := range chunks {
			_, mac, err := encryptUploadChunk(data[ch.position:ch.position+int64(ch.size)], ukey, ch.position)
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, mac)
		}
		got, err := chunkMACs(bytes.NewReader(data), ukey, chunks)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("size %d: chunkMACs disagrees with encryptUploadChunk", size)
		}
	}
}

func TestStreamingFileMACMatchesChunkMACs(t *testing.T) {
	ukey := []uint32{0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0x15161718}
	writeSteps := []int{1, 7, 16, 17, 4097, 65537}
	for _, size := range []int{0, 1, 15, 16, 17, 131072, 131073, 393217, 1048576, 3*1024*1024 + 5} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte((i*41 + 19) & 0xff)
		}
		macs, err := chunkMACs(bytes.NewReader(data), ukey, getChunkSizes(int64(size)))
		if err != nil {
			t.Fatal(err)
		}
		wantKey, err := buildFileKey(ukey, macs)
		if err != nil {
			t.Fatal(err)
		}
		sm, err := newStreamingFileMAC(wantKey, int64(size))
		if err != nil {
			t.Fatal(err)
		}
		// Feed data in irregular write sizes that cross AES block, 4 KiB scratch, and chunk boundaries.
		for off, stepIdx := 0, 0; off < len(data); stepIdx++ {
			step := writeSteps[stepIdx%len(writeSteps)]
			end := min(off+step, len(data))
			if _, err := sm.Write(data[off:end]); err != nil {
				t.Fatal(err)
			}
			off = end
		}
		if err := sm.Verify(wantKey); err != nil {
			t.Fatalf("size %d: streamingFileMAC failed verification: %v", size, err)
		}
	}
}

func TestEncryptUploadChunkDoesNotMutateInput(t *testing.T) {
	ukey := []uint32{0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0x15161718}
	for _, size := range []int{0, 1, 15, 16, 17, 64} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i + 1)
		}
		original := append([]byte(nil), data...)
		if _, _, err := encryptUploadChunk(data, ukey, 0); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, original) {
			t.Fatalf("size %d: encryptUploadChunk mutated its input", size)
		}
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
	solution, err := generateHashcashToken(context.Background(), challenge)
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

func TestGenerateHashcashTokenBoundsTheSearch(t *testing.T) {
	original := hashcashMaxAttempts
	t.Cleanup(func() { hashcashMaxAttempts = original })
	hashcashMaxAttempts = 8

	token := b64Encode(bytes.Repeat([]byte{0x5c}, 48))
	// easiness 0 -> threshold 8, i.e. ~1 in 537 million; the budget must run out.
	if _, err := generateHashcashToken(context.Background(), "1:0:1700000000:"+token); err == nil {
		t.Fatal("an unsolvable hashcash challenge did not return an error")
	}
	for _, challenge := range []string{"1:999:1700000000:" + token, "1:-1:1700000000:" + token} {
		if _, err := generateHashcashToken(context.Background(), challenge); err == nil {
			t.Fatalf("out-of-range easiness %q was accepted", challenge)
		}
	}
}

func FuzzDecryptNodeNameDoesNotPanic(f *testing.F) {
	f.Add([]byte("not-an-aes-block"), []byte("short-key"))
	f.Add(make([]byte, aes.BlockSize), make([]byte, aes.BlockSize))
	f.Fuzz(func(t *testing.T, attr, key []byte) {
		_, _ = decryptNodeName(b64Encode(attr), b64Encode(key))
	})
}
