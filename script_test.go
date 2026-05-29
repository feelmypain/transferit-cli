package main

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseTransferHandle(t *testing.T) {
	tests := map[string]string{
		"https://transfer.it/t/AbC123_-":           "AbC123_-",
		"http://www.transfer.it/t/xyz789":          "xyz789",
		"https://transfer.it/something/t/Handle42": "Handle42",
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
