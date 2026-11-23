package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestReadBoundedResponse(t *testing.T) {
	if got, err := readBoundedResponse(strings.NewReader("1234"), 4); err != nil || string(got) != "1234" {
		t.Fatalf("bounded response = %q, %v", got, err)
	}
	if _, err := readBoundedResponse(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("oversized response was accepted")
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

func TestSanitizeHTTPErrorKeepsUnrelatedText(t *testing.T) {
	u, err := url.Parse("https://example.test/cs/g?x=capability-secret-value&fn=e&pw=password-secret-value")
	if err != nil {
		t.Fatal(err)
	}
	got := sanitizeHTTPError(errors.New("dial tcp 10.0.0.1:443: connect: connection refused"), u).Error()
	// A one-character fn= value must not be redacted out of every word in the message.
	if !strings.Contains(got, "connection refused") {
		t.Fatalf("short query value shredded the error text: %s", got)
	}
	for _, secret := range []string{"capability-secret-value", "password-secret-value"} {
		if strings.Contains(got, secret) {
			t.Fatalf("sanitized error leaks %q: %s", secret, got)
		}
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
	err := (&apiClient{base: server.URL}).call(context.Background(), []map[string]any{{"a": "t"}}, nil, &out)
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

	err := (&apiClient{base: server.URL}).call(context.Background(), []map[string]any{{"a": "t"}}, nil, nil)
	var apiErr apiError
	if !errors.As(err, &apiErr) || apiErr.Code != -15 {
		t.Fatalf("err = %v, want apiError -15", err)
	}
}

func TestAPICallTransportRetryAndQueryImmutability(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		attempt := attempts
		mu.Unlock()
		if attempt == 1 {
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, err := hj.Hijack()
				if err == nil {
					conn.Close()
					return
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[0]"))
	}))
	defer server.Close()

	q := url.Values{"x": {"handle123"}}
	client := &apiClient{base: server.URL, sid: "secret-sid"}
	if err := client.call(context.Background(), []map[string]any{{"a": "xi"}}, q, nil); err != nil {
		t.Fatalf("idempotent call did not recover from transport drop: %v", err)
	}
	if q.Get("sid") != "" {
		t.Fatalf("apiClient.call mutated caller query map: %v", q)
	}

	mu.Lock()
	attempts = 0
	mu.Unlock()
	if err := client.callOnce(context.Background(), []map[string]any{{"a": "xn"}}, nil, nil); err == nil {
		t.Fatal("non-idempotent callOnce retried a transport drop")
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != 1 {
		t.Fatalf("callOnce attempts = %d, want 1", attempts)
	}
}

func TestPostUploadChunkRetriesTransientStatuses(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		attempt := attempts
		mu.Unlock()
		switch attempt {
		case 1:
			w.WriteHeader(http.StatusBadGateway)
		case 2:
			_, _ = w.Write([]byte("-3"))
		default:
			_, _ = w.Write([]byte("completion-handle"))
		}
	}))
	defer server.Close()

	body, err := postUploadChunk(context.Background(), server.URL, 0, []byte("chunk"))
	if err != nil {
		t.Fatalf("transient upload failures were not retried: %v", err)
	}
	if string(body) != "completion-handle" {
		t.Fatalf("body = %q", body)
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestPostUploadChunkDoesNotRetryPermanentFailures(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	if _, err := postUploadChunk(context.Background(), server.URL, 0, []byte("chunk")); err == nil {
		t.Fatal("a permanent failure was reported as success")
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1: permanent failures must not be retried", attempts)
	}
}

func TestPostUploadChunkStopsWhenThePoolIsCancelled(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := postUploadChunk(ctx, server.URL, 0, []byte("chunk")); err == nil {
		t.Fatal("expected an error once the worker pool is cancelled")
	}
	mu.Lock()
	defer mu.Unlock()
	// A sibling's failure must not make every worker walk the whole backoff ladder.
	if attempts > 1 {
		t.Fatalf("attempts = %d, want at most 1 after cancellation", attempts)
	}
}
