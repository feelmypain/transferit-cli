package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type apiClient struct {
	base string
	sid  string
	seq  atomic.Uint64
}

type apiError struct {
	Code int
	Body string
}

func (e apiError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("API error %d: %s", e.Code, e.Body)
	}
	return fmt.Sprintf("API error %d", e.Code)
}

// call sends an idempotent /cs command, retrying transient HTTP statuses, API
// codes (-3/-4), hashcash challenges, and transport failures.
func (c *apiClient) call(ctx context.Context, payload any, query url.Values, out any) error {
	return c.doCall(ctx, payload, query, out, true)
}

// callOnce sends a non-idempotent /cs command (such as creating a transfer or
// publishing a node): it still retries explicit transient API/HTTP responses and
// hashcash challenges, but does not retry ambiguous transport errors that could
// duplicate a server-side creation.
func (c *apiClient) callOnce(ctx context.Context, payload any, query url.Values, out any) error {
	return c.doCall(ctx, payload, query, out, false)
}

func (c *apiClient) doCall(ctx context.Context, payload any, query url.Values, out any, retryTransport bool) error {
	seq := c.seq.Add(1)
	u := fmt.Sprintf("%s/cs?id=%d", c.base, time.Now().UnixMilli()+int64(seq))
	var q url.Values
	if len(query) > 0 || c.sid != "" {
		q = make(url.Values, len(query)+1)
		for k, vals := range query {
			q[k] = append([]string(nil), vals...)
		}
		if c.sid != "" {
			q.Set("sid", c.sid)
		}
		u += "&" + q.Encode()
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	hashcash := ""
	for attempt := 0; attempt < 6; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		reqCtx, cancel := context.WithTimeout(ctx, apiRequestTimeout)
		req, err := http.NewRequestWithContext(reqCtx, "POST", u, bytes.NewReader(body))
		if err != nil {
			cancel()
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		if hashcash != "" {
			req.Header.Set("X-Hashcash", hashcash)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			sanitized := sanitizeHTTPError(err, req.URL)
			if retryTransport && attempt < 5 {
				if sleepErr := sleepWithContext(ctx, apiRetryDelay(attempt)); sleepErr != nil {
					return sleepErr
				}
				continue
			}
			return sanitized
		}
		resBody, readErr := readBoundedResponse(resp.Body, maxAPIResponseSize)
		resp.Body.Close()
		cancel()
		if readErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if retryTransport && attempt < 5 {
				if sleepErr := sleepWithContext(ctx, apiRetryDelay(attempt)); sleepErr != nil {
					return sleepErr
				}
				continue
			}
			return readErr
		}

		if resp.StatusCode == http.StatusPaymentRequired {
			challenge := resp.Header.Get("X-Hashcash")
			if challenge != "" {
				hashcash, err = generateHashcashToken(ctx, challenge)
				if err != nil {
					return err
				}
				continue
			}
		}

		if isTransientHTTPStatus(resp.StatusCode) && attempt < 5 {
			if sleepErr := sleepWithContext(ctx, apiRetryDelay(attempt)); sleepErr != nil {
				return sleepErr
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("API HTTP %s: %s", resp.Status, strings.TrimSpace(string(resBody)))
		}
		if challenge, ok := hashcashChallengeFromBody(resBody); ok {
			hashcash, err = generateHashcashToken(ctx, challenge)
			if err != nil {
				return err
			}
			continue
		}
		if code, ok := negativeAPICode(resBody); ok {
			if isTransientAPICode(code) && attempt < 5 {
				if sleepErr := sleepWithContext(ctx, apiRetryDelay(attempt)); sleepErr != nil {
					return sleepErr
				}
				continue
			}
			return apiError{Code: code, Body: strings.TrimSpace(string(resBody))}
		}
		if code, ok := firstNegativeArrayCode(resBody); ok {
			if isTransientAPICode(code) && attempt < 5 {
				if sleepErr := sleepWithContext(ctx, apiRetryDelay(attempt)); sleepErr != nil {
					return sleepErr
				}
				continue
			}
			return apiError{Code: code, Body: strings.TrimSpace(string(resBody))}
		}
		if out == nil {
			return nil
		}
		return json.Unmarshal(resBody, out)
	}
	return errors.New("API hashcash challenge did not resolve after retries")
}

// postUploadChunk retries transient failures instead of letting one blip cancel the
// worker pool and discard a multi-gigabyte upload that cannot be resumed. Chunk POSTs
// are addressed by byte offset and idempotent, so re-posting is safe — including the
// final chunk, which returns the completion handle again.
func postUploadChunk(parent context.Context, uploadURL string, offset int64, data []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < uploadChunkAttempts; attempt++ {
		if attempt > 0 {
			if err := sleepWithContext(parent, apiRetryDelay(attempt-1)); err != nil {
				return nil, err
			}
		}
		body, retryable, err := postUploadChunkOnce(parent, uploadURL, offset, data)
		if err == nil {
			return body, nil
		}
		lastErr = err
		// A sibling worker's failure cancels parent; do not burn the backoff ladder.
		if !retryable || parent.Err() != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

// postUploadChunkOnce reports whether the failure it returns is worth retrying. The
// per-attempt timeout lives here rather than around the whole loop so a stalled
// connection that burns the full budget still leaves room for another attempt.
func postUploadChunkOnce(parent context.Context, uploadURL string, offset int64, data []byte) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(parent, uploadChunkTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/%d", uploadURL, offset), bytes.NewReader(data))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, parent.Err() == nil, sanitizeHTTPError(err, req.URL)
	}
	defer resp.Body.Close()
	body, err := readBoundedResponse(resp.Body, maxUploadResponseSize)
	if err != nil {
		return nil, parent.Err() == nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, isTransientHTTPStatus(resp.StatusCode), fmt.Errorf("upload HTTP %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if code, ok := negativeAPICode(body); ok {
		return nil, isTransientAPICode(code), apiError{Code: code, Body: strings.TrimSpace(string(body))}
	}
	return body, false, nil
}

func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{
		Timeout:   connectionSetupTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.TLSHandshakeTimeout = connectionSetupTimeout
	transport.ResponseHeaderTimeout = responseHeaderTimeout
	// DefaultTransport pools only 2 idle connections per host, so parallel upload
	// workers would re-handshake on every chunk. Match the --upload-workers ceiling.
	transport.MaxIdleConnsPerHost = 16
	return &http.Client{Transport: transport}
}

func readBoundedResponse(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("HTTP response exceeds %d bytes", limit)
	}
	return body, nil
}

func sanitizeHTTPError(err error, requestURL *url.URL) error {
	detail := err.Error()
	safeTarget := requestURL.Scheme + "://" + requestURL.Host
	detail = strings.ReplaceAll(detail, requestURL.String(), safeTarget)
	query := requestURL.Query()
	for _, values := range query {
		for _, value := range values {
			// Short values (a one-character file name in fn=, say) match everywhere
			// and would shred the surrounding message. Every secret carried here —
			// sid, pw, and the capability-bearing x — is far longer than this.
			if len(value) < 8 {
				continue
			}
			detail = strings.ReplaceAll(detail, value, "[redacted]")
			if escaped := url.QueryEscape(value); escaped != value {
				detail = strings.ReplaceAll(detail, escaped, "[redacted]")
			}
		}
	}
	return errors.New(detail)
}

func rawList(raw []json.RawMessage) string {
	b, _ := json.Marshal(raw)
	return string(b)
}

func negativeAPICode(body []byte) (int, bool) {
	s := strings.TrimSpace(string(body))
	if s == "" || !strings.HasPrefix(s, "-") {
		return 0, false
	}
	code, err := strconv.Atoi(s)
	return code, err == nil
}

func firstNegativeArrayCode(body []byte) (int, bool) {
	var raw []json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || len(raw) == 0 {
		return 0, false
	}
	return negativeAPICode(raw[0])
}

func isInvalidSessionError(err error) bool {
	var apiErr apiError
	return errors.As(err, &apiErr) && apiErr.Code == -15
}

func isTransientAPICode(code int) bool {
	return code == -3 || code == -4
}

func isTransientHTTPStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func apiRetryDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 5 {
		attempt = 5
	}
	return time.Duration(250*(1<<attempt)) * time.Millisecond
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
