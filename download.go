package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

func runDownload(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("download", flag.ContinueOnError)
	password := fs.String("password", "", "transfer password")
	outDir := fs.String("out", ".", "output directory")
	if err := fs.Parse(reorderFlagsFirst(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("download requires exactly one transfer.it URL")
	}

	xh, err := parseTransferHandle(fs.Arg(0))
	if err != nil {
		return err
	}

	pwToken := ""
	info, err := getTransferInfo(ctx, xh)
	if err != nil {
		return err
	}
	if info.Password != 0 {
		pass := strings.TrimSpace(*password)
		if pass == "" {
			entered, err := promptSecret(ctx, "Password: ")
			if err != nil {
				return fmt.Errorf("password required: %w", err)
			}
			pass = strings.TrimSpace(entered)
		}
		pwToken, err = deriveTransferPassword(xh, pass)
		if err != nil {
			return err
		}
		if err := validateTransferPassword(ctx, xh, pwToken); err != nil {
			return err
		}
	}

	nodes, err := fetchNodes(ctx, xh, pwToken)
	if err != nil {
		return err
	}
	files := make([]transferNode, 0)
	folders := make([]transferNode, 0)
	hasChildFolder := false
	for _, n := range nodes {
		if n.T == 0 {
			files = append(files, n)
		} else if n.T == 1 {
			folders = append(folders, n)
			if n.P != "" {
				hasChildFolder = true
			}
		}
	}
	if len(files) == 0 && !hasChildFolder {
		return errors.New("transfer contains no downloadable files or folders")
	}

	outputRoot, err := filepath.Abs(*outDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outputRoot, 0755); err != nil {
		return err
	}
	outputRoot, err = filepath.EvalSymlinks(outputRoot)
	if err != nil {
		return err
	}
	baseDir := outputRoot
	if len(files) > 1 || hasChildFolder {
		title := decodeMaybeBase64(info.Title)
		if title == "" {
			title = xh
		}
		baseDir, err = resolveDownloadPath(outputRoot, safeName(title))
		if err != nil {
			return err
		}
	}

	reserver := newPathReserver()
	folderPaths := make([]string, 0, len(folders))
	for _, folder := range folders {
		if folder.P == "" || folder.Path == "" {
			continue
		}
		dst, err := resolveDownloadPath(baseDir, folder.Path)
		if err != nil {
			return fmt.Errorf("invalid folder path %q: %w", folder.Path, err)
		}
		if err := reserver.reserveFolder(dst, "folder "+folder.Path); err != nil {
			return err
		}
		folderPaths = append(folderPaths, dst)
	}

	type fileDownload struct {
		node transferNode
		dst  string
	}
	downloads := make([]fileDownload, 0, len(files))
	for _, file := range files {
		rel := file.Path
		if rel == "" {
			rel = file.Name
		}
		dst, err := resolveDownloadPath(baseDir, rel)
		if err != nil {
			return fmt.Errorf("invalid file path %q: %w", rel, err)
		}
		reserved, err := reserver.reserveFile(dst, "file "+rel)
		if err != nil {
			return err
		}
		if reserved != dst {
			fmt.Printf("Renaming %s to %s to avoid a local name collision\n", rel, filepath.Base(reserved))
		}
		downloads = append(downloads, fileDownload{node: file, dst: reserved})
	}

	if err := rejectSymlinkComponents(outputRoot, baseDir); err != nil {
		return err
	}
	for _, dst := range folderPaths {
		if err := rejectSymlinkComponents(outputRoot, dst); err != nil {
			return err
		}
	}
	for _, download := range downloads {
		if err := rejectSymlinkComponents(outputRoot, download.dst); err != nil {
			return err
		}
	}
	outputHandle, err := os.OpenRoot(outputRoot)
	if err != nil {
		return err
	}
	defer outputHandle.Close()
	baseRel, err := filepath.Rel(outputRoot, baseDir)
	if err != nil {
		return err
	}
	if err := outputHandle.MkdirAll(baseRel, 0755); err != nil {
		return err
	}
	downloadRoot, err := outputHandle.OpenRoot(baseRel)
	if err != nil {
		return err
	}
	defer downloadRoot.Close()
	for _, dst := range folderPaths {
		rel, err := filepath.Rel(baseDir, dst)
		if err != nil {
			return err
		}
		if err := downloadRoot.MkdirAll(rel, 0755); err != nil {
			return err
		}
	}
	for _, download := range downloads {
		rel, err := filepath.Rel(baseDir, download.dst)
		if err != nil {
			return err
		}
		if err := downloadNode(ctx, downloadRoot, xh, pwToken, download.node, rel, download.dst); err != nil {
			return err
		}
	}
	return nil
}

func parseTransferHandle(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		host := strings.ToLower(u.Hostname())
		if host != "transfer.it" && host != "www.transfer.it" {
			return "", fmt.Errorf("unsupported transfer host %q", u.Host)
		}
		if handle := transferHandleFromPath(u.Path); handle != "" {
			return handle, nil
		}
	}
	if m := linkRE.FindStringSubmatch(raw); len(m) == 2 {
		return m[1], nil
	}
	return "", fmt.Errorf("could not parse transfer handle from %q", raw)
}

func transferHandleFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "t" && parts[i+1] != "" {
			return parts[i+1]
		}
	}
	return ""
}

func getTransferInfo(ctx context.Context, xh string) (transferInfo, error) {
	var out []transferInfo
	err := (&apiClient{base: transferAPI}).call(ctx, []map[string]any{{"a": "xi", "xh": xh}}, nil, &out)
	if err != nil {
		return transferInfo{}, err
	}
	if len(out) != 1 {
		return transferInfo{}, errors.New("unexpected xi response")
	}
	return out[0], nil
}

func validateTransferPassword(ctx context.Context, xh, token string) error {
	var out []json.RawMessage
	err := (&apiClient{base: transferAPI}).call(ctx, []map[string]any{{"a": "xv", "xh": xh, "pw": token}}, nil, &out)
	if err != nil {
		var apiErr apiError
		if errors.As(err, &apiErr) && apiErr.Code == -14 {
			return errors.New("invalid transfer password")
		}
		return err
	}
	if len(out) != 1 || string(out[0]) != "1" {
		return errors.New("invalid transfer password")
	}
	return nil
}

func fetchNodes(ctx context.Context, xh, pwToken string) ([]transferNode, error) {
	q := url.Values{"x": {xh}}
	if pwToken != "" {
		q.Set("pw", pwToken)
	}
	var out []struct {
		F []transferNode `json:"f"`
	}
	if err := (&apiClient{base: transferAPI}).call(ctx, []map[string]any{{"a": "f", "c": 1, "r": 1}}, q, &out); err != nil {
		return nil, err
	}
	if len(out) != 1 {
		return nil, errors.New("unexpected f response")
	}
	nodes := out[0].F
	byHandle := make(map[string]*transferNode, len(nodes))
	for i := range nodes {
		if nodes[i].H == "" {
			return nil, fmt.Errorf("node %d has an empty handle", i)
		}
		if _, exists := byHandle[nodes[i].H]; exists {
			return nil, fmt.Errorf("duplicate node handle %q", nodes[i].H)
		}
		if nodes[i].T == 0 && nodes[i].S < 0 {
			return nil, fmt.Errorf("file node %q has negative size %d", nodes[i].H, nodes[i].S)
		}
		name, err := decryptNodeName(nodes[i].A, nodes[i].K)
		if err != nil && (nodes[i].T == 0 || nodes[i].T == 1) {
			return nil, fmt.Errorf("decrypt node %q attributes: %w", nodes[i].H, err)
		}
		if name != "" {
			nodes[i].Name = name
		}
		if nodes[i].Name == "" {
			nodes[i].Name = nodes[i].H
		}
		byHandle[nodes[i].H] = &nodes[i]
	}
	for i := range nodes {
		var err error
		nodes[i].Path, err = buildNodePath(&nodes[i], byHandle)
		if err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func buildNodePath(n *transferNode, byHandle map[string]*transferNode) (string, error) {
	parts := []string{safeName(n.Name)}
	visited := map[string]bool{n.H: true}
	for p := n.P; p != ""; {
		if visited[p] {
			return "", fmt.Errorf("node parent cycle involving %q", p)
		}
		visited[p] = true
		parent := byHandle[p]
		if parent == nil {
			return "", fmt.Errorf("node %q references missing parent %q", n.H, p)
		}
		if parent.P == "" {
			break
		}
		parts = append(parts, safeName(parent.Name))
		p = parent.P
	}
	slices.Reverse(parts)
	return strings.Join(parts, "/"), nil
}

func resolveDownloadPath(baseDir, rel string) (string, error) {
	root, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}
	native := filepath.FromSlash(rel)
	if strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "\\") || filepath.IsAbs(native) || filepath.VolumeName(native) != "" {
		return "", errors.New("absolute paths are not allowed")
	}
	dst := filepath.Join(root, native)
	within, err := filepath.Rel(root, dst)
	if err != nil {
		return "", err
	}
	if within == ".." || strings.HasPrefix(within, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes the output directory")
	}
	return dst, nil
}

func rejectSymlinkComponents(baseDir, dst string) error {
	rel, err := filepath.Rel(baseDir, dst)
	if err != nil {
		return err
	}
	current := baseDir
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		st, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("download path contains symlink: %s", current)
		}
	}
	return nil
}

// reservedPath records which remote node claimed a local destination, and whether
// that destination is a directory. Two remote names that are distinct on the server
// can still land on the same local path after safeName sanitization or Unicode/case
// folding, so every destination is reserved before the first byte is fetched.
type reservedPath struct {
	label string
	isDir bool
}

type pathReserver struct {
	seen   map[string]reservedPath
	folder cases.Caser
}

func newPathReserver() *pathReserver {
	return &pathReserver{
		seen:   map[string]reservedPath{},
		folder: cases.Fold(),
	}
}

func (r *pathReserver) reserveFolder(dst, label string) error {
	key := portableDownloadPathKeyWith(&r.folder, dst)
	if prev, ok := r.seen[key]; ok {
		if !prev.isDir {
			return fmt.Errorf("download path collision: %s and %s both map to %s", prev.label, label, filepath.Clean(dst))
		}
		return nil
	}
	r.seen[key] = reservedPath{label: label, isDir: true}
	return nil
}

func (r *pathReserver) reserveFile(dst, label string) (string, error) {
	dir, base := filepath.Split(dst)
	dirKey := ""
	if dir != "" {
		dirKey = portableDownloadPathKeyWith(&r.folder, dir)
	}
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	candidateBase := base
	candidate := dst
	for n := 1; ; n++ {
		key := joinPortableKey(dirKey, normalizePathComponent(&r.folder, candidateBase))
		partKey := joinPortableKey(dirKey, normalizePathComponent(&r.folder, candidateBase+".part"))
		prev, taken := r.seen[key]
		prevPart, partTaken := r.seen[partKey]
		if !taken && !partTaken {
			r.seen[key] = reservedPath{label: label}
			r.seen[partKey] = reservedPath{label: "partial " + label}
			return candidate, nil
		}
		if (taken && prev.isDir) || (partTaken && prevPart.isDir) {
			blocker := prev.label
			if prevPart.isDir {
				blocker = prevPart.label
			}
			return "", fmt.Errorf("download path collision: %s and %s both map to %s", blocker, label, filepath.Clean(candidate))
		}
		if n > maxPathDisambiguation {
			return "", fmt.Errorf("could not find a free download path for %s near %s", label, filepath.Clean(dst))
		}
		candidateBase = fmt.Sprintf("%s (%d)%s", stem, n, ext)
		candidate = filepath.Join(dir, candidateBase)
	}
}

// reserveFolderPath claims dst for a directory. Directories merge on collision:
// renaming one would be unsound because buildNodePath derives child paths
// independently and would not follow the rename. Real conflicts between their
// contents are caught later by reserveFilePath.
func reserveFolderPath(seen map[string]reservedPath, dst, label string) error {
	return (&pathReserver{seen: seen, folder: cases.Fold()}).reserveFolder(dst, label)
}

// reserveFilePath claims dst and its .part sidecar for a file, appending " (n)" to
// the stem until both are free. Disambiguating keeps the rest of the transfer
// downloadable instead of failing the whole run over one collision, while still
// guaranteeing no two nodes ever write to the same local file.
func reserveFilePath(seen map[string]reservedPath, dst, label string) (string, error) {
	return (&pathReserver{seen: seen, folder: cases.Fold()}).reserveFile(dst, label)
}

func normalizePathComponent(folder *cases.Caser, part string) string {
	return folder.String(norm.NFC.String(strings.TrimRight(part, " .")))
}

func joinPortableKey(dirKey, baseKey string) string {
	if dirKey == "" {
		return "/" + baseKey
	}
	if strings.HasSuffix(dirKey, "/") {
		return dirKey + baseKey
	}
	return dirKey + "/" + baseKey
}

func portableDownloadPathKey(path string) string {
	folder := cases.Fold()
	return portableDownloadPathKeyWith(&folder, path)
}

func portableDownloadPathKeyWith(folder *cases.Caser, path string) string {
	vol := filepath.VolumeName(path)
	volume := strings.ToLower(vol)
	rest := strings.TrimPrefix(filepath.Clean(path), vol)
	parts := strings.FieldsFunc(filepath.ToSlash(rest), func(r rune) bool { return r == '/' })
	for i := range parts {
		parts[i] = normalizePathComponent(folder, parts[i])
	}
	return volume + "/" + strings.Join(parts, "/")
}

func downloadNode(ctx context.Context, root *os.Root, xh, pwToken string, n transferNode, rel, displayPath string) error {
	if err := root.MkdirAll(filepath.Dir(rel), 0755); err != nil {
		return err
	}
	if st, err := root.Lstat(rel); err == nil {
		if !st.Mode().IsRegular() {
			return fmt.Errorf("download destination is not a regular file: %s", displayPath)
		}
		if st.Size() == n.S {
			if err := verifyDownloadedFileInRoot(root, rel, n); err == nil {
				fmt.Printf("Already complete: %s (%d bytes, verified)\n", displayPath, n.S)
				return nil
			} else {
				fmt.Printf("Existing file failed integrity check, redownloading: %v\n", err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	partRel := rel + ".part"
	existing := int64(0)
	if st, err := root.Lstat(partRel); err == nil {
		if !st.Mode().IsRegular() {
			return fmt.Errorf("partial download is not a regular file: %s.part", displayPath)
		}
		existing = st.Size()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if existing == n.S {
		if err := verifyDownloadedFileInRoot(root, partRel, n); err == nil {
			return root.Rename(partRel, rel)
		}
		existing = 0
	}
	if existing > n.S {
		existing = 0
	}

	resumed, verified, err := downloadNodeWithRetry(ctx, root, xh, pwToken, n, partRel, displayPath+".part", existing)
	if err != nil {
		return err
	}
	if !verified {
		if err := verifyDownloadedFileInRoot(root, partRel, n); err != nil {
			if !resumed {
				return fmt.Errorf("downloaded file failed integrity check: %w", err)
			}
			fmt.Printf("Integrity check failed after resume, retrying from start: %v\n", err)
			_, retryVerified, retryErr := downloadNodeWithRetry(ctx, root, xh, pwToken, n, partRel, displayPath+".part", 0)
			if retryErr != nil {
				return retryErr
			}
			if !retryVerified {
				if verifyErr := verifyDownloadedFileInRoot(root, partRel, n); verifyErr != nil {
					return fmt.Errorf("downloaded file failed integrity check after retry: %w", verifyErr)
				}
			}
		}
	}
	return root.Rename(partRel, rel)
}

// downloadNodeWithRetry fetches a node into its .part file, absorbing transient
// network failures instead of aborting every remaining file in the transfer. Each
// attempt re-measures what actually landed on disk and resumes from there; only a
// resume the server explicitly refuses restarts from byte zero, because
// downloadNodeBytes truncates when existing == 0.
func downloadNodeWithRetry(ctx context.Context, root *os.Root, xh, pwToken string, n transferNode, rel, displayPath string, existing int64) (resumed bool, verified bool, err error) {
	resumed = existing > 0
	var lastErr error
	for attempt := 0; attempt < downloadAttempts; attempt++ {
		if existing > 0 {
			resumed = true
		}
		verified, err = downloadNodeBytes(ctx, root, xh, pwToken, n, rel, displayPath, existing)
		if err == nil {
			return resumed, verified, nil
		}
		lastErr = err
		switch {
		case errors.Is(err, errRangeRejected) && existing > 0:
			fmt.Printf("Server refused to resume %s, restarting from the beginning: %v\n", displayPath, err)
			existing = 0
			resumed = false
		case errors.Is(err, errDownloadTransient) && attempt < downloadAttempts-1:
			if sleepErr := sleepWithContext(ctx, apiRetryDelay(attempt)); sleepErr != nil {
				return resumed, false, sleepErr
			}
			existing = 0
			if st, statErr := root.Lstat(rel); statErr == nil && st.Mode().IsRegular() && st.Size() <= n.S {
				existing = st.Size()
			}
			if existing > 0 {
				resumed = true
			}
			fmt.Printf("Download of %s failed (%v); retrying from %d bytes\n", displayPath, err, existing)
		default:
			return resumed, false, err
		}
	}
	return resumed, false, lastErr
}

func downloadNodeBytes(ctx context.Context, root *os.Root, xh, pwToken string, n transferNode, rel, displayPath string, existing int64) (bool, error) {
	downloadURL := fmt.Sprintf("%s/cs/g?x=%s&n=%s&fn=%s", transferAPI, url.QueryEscape(xh), url.QueryEscape(n.H), url.QueryEscape(n.Name))
	if pwToken != "" {
		downloadURL += "&pw=" + url.QueryEscape(pwToken)
	}

	reqCtx, reqCancel := context.WithCancel(ctx)
	defer reqCancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", downloadURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Referer", origin+"/t/"+xh)
	req.Header.Set("Origin", origin)
	if existing > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", existing))
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, fmt.Errorf("%w: %w", errDownloadTransient, sanitizeHTTPError(err, req.URL))
	}
	defer resp.Body.Close()
	if existing > 0 && resp.StatusCode == http.StatusOK {
		existing = 0
	}

	idleBody := newIdleTimeoutReader(resp.Body, downloadIdleTimeout, reqCancel)
	defer idleBody.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		body, _ := io.ReadAll(io.LimitReader(idleBody, 4096))
		statusErr := fmt.Errorf("download HTTP %s: %s", resp.Status, strings.TrimSpace(string(body)))
		switch {
		case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
			return false, fmt.Errorf("%w: %w", errRangeRejected, statusErr)
		case isTransientHTTPStatus(resp.StatusCode):
			return false, fmt.Errorf("%w: %w", errDownloadTransient, statusErr)
		}
		return false, statusErr
	}
	if resp.StatusCode == http.StatusPartialContent {
		if existing == 0 {
			return false, errors.New("download server returned an unexpected partial response")
		}
		if err := validateContentRange(resp.Header.Get("Content-Range"), existing, n.S); err != nil {
			return false, fmt.Errorf("%w: %w", errRangeRejected, err)
		}
	}

	var (
		fileKey   []uint32
		macWriter *streamingFileMAC
	)
	if existing == 0 {
		fileKey, err = decodeFileKey(n.K)
		if err != nil {
			return false, err
		}
		macWriter, err = newStreamingFileMAC(fileKey, n.S)
		if err != nil {
			return false, err
		}
	}

	flags := os.O_CREATE | os.O_WRONLY
	if existing > 0 {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	f, err := root.OpenFile(rel, flags, 0644)
	if err != nil {
		return false, err
	}
	fmt.Printf("Downloading %s -> %s\n", n.Name, displayPath)
	remaining := n.S - existing
	limited := &io.LimitedReader{R: idleBody, N: remaining + 1}
	var dst io.Writer = f
	if macWriter != nil {
		dst = io.MultiWriter(f, macWriter)
	}
	copyErr := copyWithProgress(dst, limited, existing, n.S)
	closeErr := f.Close()
	if copyErr != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		// A reset or stall mid-body is retryable; the bytes already flushed stay put.
		return false, fmt.Errorf("%w: %w", errDownloadTransient, copyErr)
	}
	if closeErr != nil {
		return false, closeErr
	}
	if limited.N == 0 {
		return false, fmt.Errorf("download exceeded expected size of %d bytes", n.S)
	}
	st, err := root.Stat(rel)
	if err != nil {
		return false, err
	}
	if st.Size() != n.S {
		return false, fmt.Errorf("%w: download ended at %d bytes, want %d", errDownloadTransient, st.Size(), n.S)
	}
	if macWriter != nil {
		if err := macWriter.Verify(fileKey); err != nil {
			return false, fmt.Errorf("downloaded file failed integrity check: %w", err)
		}
		return true, nil
	}
	return false, nil
}

func validateContentRange(header string, start, total int64) error {
	if !strings.HasPrefix(header, "bytes ") {
		return fmt.Errorf("invalid Content-Range %q", header)
	}
	byteRange, totalText, ok := strings.Cut(strings.TrimPrefix(header, "bytes "), "/")
	if !ok {
		return fmt.Errorf("invalid Content-Range %q", header)
	}
	startText, endText, ok := strings.Cut(byteRange, "-")
	if !ok {
		return fmt.Errorf("invalid Content-Range %q", header)
	}
	gotStart, startErr := strconv.ParseInt(startText, 10, 64)
	gotEnd, endErr := strconv.ParseInt(endText, 10, 64)
	gotTotal, totalErr := strconv.ParseInt(totalText, 10, 64)
	if startErr != nil || endErr != nil || totalErr != nil || gotStart != start || gotEnd != total-1 || gotTotal != total {
		return fmt.Errorf("unexpected Content-Range %q, want bytes %d-%d/%d", header, start, total-1, total)
	}
	return nil
}

// idleTimeoutReader aborts a stalled Read by invoking cancel (typically the HTTP
// request's CancelFunc) when no bytes arrive within timeout. One reusable timer
// avoids spawning a goroutine per Read and avoids leaking readers on timeout.
type idleTimeoutReader struct {
	reader   io.Reader
	timeout  time.Duration
	cancel   context.CancelFunc
	timer    *time.Timer
	timedOut atomic.Bool
}

func newIdleTimeoutReader(r io.Reader, timeout time.Duration, cancel context.CancelFunc) *idleTimeoutReader {
	ir := &idleTimeoutReader{
		reader:  r,
		timeout: timeout,
		cancel:  cancel,
	}
	ir.timer = time.AfterFunc(math.MaxInt64, func() {
		ir.timedOut.Store(true)
		if ir.cancel != nil {
			ir.cancel()
		}
	})
	ir.timer.Stop()
	return ir
}

func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	r.timer.Reset(r.timeout)
	n, err := r.reader.Read(p)
	r.timer.Stop()
	if err != nil && !errors.Is(err, io.EOF) && r.timedOut.Load() {
		return n, fmt.Errorf("%w: download stalled for %s", errDownloadTransient, r.timeout)
	}
	return n, err
}

func (r *idleTimeoutReader) Close() {
	r.timer.Stop()
}

func verifyDownloadedFile(path string, n transferNode) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return verifyDownloadedReader(f, n)
}

func verifyDownloadedFileInRoot(root *os.Root, path string, n transferNode) error {
	f, err := root.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return verifyDownloadedReader(f, n)
}

func verifyDownloadedReader(f *os.File, n transferNode) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("download is not a regular file")
	}
	if st.Size() != n.S {
		return fmt.Errorf("size mismatch: got %d bytes, want %d bytes", st.Size(), n.S)
	}
	fileKey, err := decodeFileKey(n.K)
	if err != nil {
		return err
	}
	macWriter, err := newStreamingFileMAC(fileKey, n.S)
	if err != nil {
		return err
	}
	if n.S > 0 {
		buf := make([]byte, 256*1024)
		if _, err := io.CopyBuffer(macWriter, f, buf); err != nil {
			return err
		}
	}
	return macWriter.Verify(fileKey)
}
