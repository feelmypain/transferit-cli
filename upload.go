package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func runUpload(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("upload", flag.ContinueOnError)
	title := fs.String("title", "", "transfer title")
	message := fs.String("message", "", "message")
	from := fs.String("from", "", "sender email")
	password := fs.String("password", "", "link password")
	expire := fs.Int("expire", 90, "expiry in days: 90, 30, 7, or 0")
	to := fs.String("to", "", "comma-separated recipient emails")
	sendAt := fs.String("send-at", "", "scheduled send time, Unix seconds or RFC3339")
	useAccount := fs.Bool("account", false, "use saved/logged-in MEGA account session")
	accountEmail := fs.String("account-email", "", "MEGA account email for one-shot login")
	accountPassword := fs.String("account-password", "", "MEGA account password for one-shot login")
	accountMFA := fs.String("account-mfa", "", "MEGA account two-factor code")
	saveAccountPassword := fs.Bool("save-account-password", false, "save account password when logging in during upload")
	uploadWorkers := fs.Int("upload-workers", 4, "parallel upload chunk workers")
	if err := fs.Parse(reorderFlagsFirst(fs, args)); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("upload requires at least one file")
	}
	if *expire != 0 && *expire != 7 && *expire != 30 && *expire != 90 {
		return errors.New("--expire must be one of 0, 7, 30, or 90")
	}
	if *uploadWorkers < 1 || *uploadWorkers > 16 {
		return errors.New("--upload-workers must be between 1 and 16")
	}
	recipients := splitEmails(*to)
	schedule, err := parseSchedule(*sendAt)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*sendAt) != "" && len(recipients) == 0 {
		return errors.New("--send-at requires at least one --to recipient")
	}
	if strings.TrimSpace(*sendAt) != "" && schedule <= time.Now().Unix() {
		return errors.New("--send-at must be in the future")
	}

	paths := fs.Args()
	items, err := collectUploadItems(paths)
	if err != nil {
		return err
	}

	name := strings.TrimSpace(*title)
	if name == "" {
		if len(paths) == 1 {
			absolute, err := filepath.Abs(paths[0])
			if err != nil {
				return err
			}
			name = filepath.Base(absolute)
		} else {
			name = "Transfer.it " + time.Now().UTC().Format("2006-01-02 15:04:05")
		}
	}

	sess, sessionLabel, err := resolveUploadSession(ctx, *useAccount, strings.TrimSpace(*accountEmail), *accountPassword, strings.TrimSpace(*accountMFA), *saveAccountPassword)
	if err != nil {
		return err
	}
	fmt.Printf("Using %s.\n", sessionLabel)
	tapi := &apiClient{base: transferAPI, sid: sess.sid}

	root, xh, err := createTransfer(ctx, tapi, name)
	if err != nil && *useAccount && isInvalidSessionError(err) {
		fmt.Println("Saved account session was rejected; refreshing MEGA login...")
		sess, sessionLabel, err = refreshAccountSession(ctx, strings.TrimSpace(*accountEmail), *accountPassword, strings.TrimSpace(*accountMFA), *saveAccountPassword)
		if err != nil {
			return err
		}
		fmt.Printf("Using %s.\n", sessionLabel)
		tapi = &apiClient{base: transferAPI, sid: sess.sid}
		root, xh, err = createTransfer(ctx, tapi, name)
	}
	if err != nil {
		return err
	}
	fmt.Printf("Transfer created: https://transfer.it/t/%s\n", xh)

	folderHandles, err := createRemoteFolders(ctx, tapi, root, items)
	if err != nil {
		return err
	}

	results := make([]uploadResult, 0, len(items))
	for _, item := range items {
		if item.IsDir {
			continue
		}
		parentRel := pathpkg.Dir(item.Rel)
		if parentRel == "." {
			parentRel = ""
		}
		parent := folderHandles[parentRel]
		if parent == "" {
			return fmt.Errorf("missing remote parent folder for %s", item.Rel)
		}
		res, err := uploadFile(ctx, tapi, parent, item.Source, pathpkg.Base(item.Rel), item.Rel, *uploadWorkers)
		if err != nil {
			return err
		}
		results = append(results, res)
	}

	if err := setTransferOptions(ctx, tapi, xh, transferOptions{
		Title:    name,
		Message:  strings.TrimSpace(*message),
		From:     strings.TrimSpace(*from),
		Password: strings.TrimSpace(*password),
		Expire:   *expire,
	}); err != nil {
		return err
	}

	if len(recipients) > 0 {
		if schedule != 0 && schedule <= time.Now().Unix() {
			return errors.New("--send-at elapsed before the upload completed")
		}
		for _, email := range recipients {
			if err := setTransferRecipient(ctx, tapi, xh, email, schedule); err != nil {
				return err
			}
		}
	}

	if err := closeTransfer(ctx, tapi, xh); err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("Link: https://transfer.it/t/%s\n", xh)
	for _, res := range results {
		fmt.Printf("Uploaded: %s (%d bytes, node %s)\n", res.Path, res.Size, res.Handle)
	}
	if len(recipients) > 0 {
		fmt.Printf("Recipients queued: %s\n", strings.Join(recipients, ", "))
	}
	return nil
}

func collectUploadItems(paths []string) ([]uploadItem, error) {
	var items []uploadItem
	seen := map[string]bool{}
	for _, input := range paths {
		clean := filepath.Clean(input)
		st, err := os.Lstat(clean)
		if err != nil {
			return nil, err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink is not supported: %s", input)
		}
		if !st.IsDir() {
			if !st.Mode().IsRegular() {
				return nil, fmt.Errorf("not a regular file: %s", input)
			}
			rel := filepath.Base(clean)
			if seen[rel] {
				return nil, fmt.Errorf("duplicate upload path %q", rel)
			}
			seen[rel] = true
			items = append(items, uploadItem{Source: clean, Rel: rel, Size: st.Size()})
			continue
		}

		absolute, err := filepath.Abs(clean)
		if err != nil {
			return nil, err
		}
		rootName := filepath.Base(absolute)
		if rootName == "." || rootName == string(filepath.Separator) || rootName == "" {
			return nil, fmt.Errorf("cannot upload filesystem root %q", input)
		}
		err = filepath.WalkDir(clean, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			inside, err := filepath.Rel(clean, path)
			if err != nil {
				return err
			}
			rel := filepath.ToSlash(filepath.Join(rootName, inside))
			if inside == "." {
				rel = filepath.ToSlash(rootName)
			}
			if seen[rel] {
				return fmt.Errorf("duplicate upload path %q", rel)
			}
			seen[rel] = true
			switch {
			case d.IsDir():
				items = append(items, uploadItem{Source: path, Rel: rel, IsDir: true})
			case info.Mode().IsRegular():
				items = append(items, uploadItem{Source: path, Rel: rel, Size: info.Size()})
			default:
				return fmt.Errorf("special file is not supported: %s", path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return items, nil
}

func createTransfer(ctx context.Context, api *apiClient, title string) (root, xh string, err error) {
	key, err := randomWords(4)
	if err != nil {
		return "", "", err
	}
	attr, err := encryptAttr(map[string]any{"t": time.Now().Unix(), "n": title}, key)
	if err != nil {
		return "", "", err
	}
	var res [][]string
	err = api.callOnce(ctx, []map[string]any{{"a": "xn", "at": attr, "k": b64Encode(wordsToBytes(key))}}, nil, &res)
	if err != nil {
		return "", "", err
	}
	if len(res) != 1 || len(res[0]) != 2 {
		return "", "", fmt.Errorf("unexpected xn response: %+v", res)
	}
	xh, root = res[0][0], res[0][1]
	return root, xh, nil
}

func createRemoteFolders(ctx context.Context, api *apiClient, root string, items []uploadItem) (map[string]string, error) {
	handles := map[string]string{"": root}
	for _, item := range items {
		if !item.IsDir {
			continue
		}
		parentRel := pathpkg.Dir(item.Rel)
		if parentRel == "." {
			parentRel = ""
		}
		parent := handles[parentRel]
		if parent == "" {
			return nil, fmt.Errorf("missing remote parent folder for %s", item.Rel)
		}
		handle, err := createRemoteFolder(ctx, api, parent, pathpkg.Base(item.Rel))
		if err != nil {
			return nil, err
		}
		handles[item.Rel] = handle
		fmt.Printf("Created folder: %s\n", item.Rel)
	}
	return handles, nil
}

func createRemoteFolder(ctx context.Context, api *apiClient, parent, name string) (string, error) {
	key, err := randomWords(4)
	if err != nil {
		return "", err
	}
	attr, err := encryptAttr(map[string]any{"n": name}, key)
	if err != nil {
		return "", err
	}
	node := map[string]any{
		"h": "xxxxxxxx",
		"t": 1,
		"a": attr,
		"k": b64Encode(wordsToBytes(key)),
	}
	var xpRes []struct {
		F []struct {
			H string `json:"h"`
		} `json:"f"`
	}
	if err := api.callOnce(ctx, []map[string]any{{"a": "xp", "v": 3, "t": parent, "n": []map[string]any{node}}}, nil, &xpRes); err != nil {
		return "", err
	}
	if len(xpRes) != 1 || len(xpRes[0].F) != 1 || xpRes[0].F[0].H == "" {
		return "", fmt.Errorf("unexpected folder xp response: %+v", xpRes)
	}
	return xpRes[0].F[0].H, nil
}

func uploadFile(ctx context.Context, api *apiClient, root, filePath, remoteName, displayPath string, uploadWorkers int) (uploadResult, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return uploadResult{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return uploadResult{}, err
	}
	if !st.Mode().IsRegular() {
		return uploadResult{}, fmt.Errorf("not a regular file: %s", filePath)
	}
	size := st.Size()

	var upRes []struct {
		P string `json:"p"`
	}
	if err := api.call(ctx, []map[string]any{{"a": "u", "s": size, "ssl": 2}}, nil, &upRes); err != nil {
		return uploadResult{}, err
	}
	if len(upRes) != 1 || upRes[0].P == "" {
		return uploadResult{}, errors.New("unexpected upload URL response")
	}

	ukey, err := randomWords(6)
	if err != nil {
		return uploadResult{}, err
	}
	chunks := getChunkSizes(size)
	if len(chunks) == 0 {
		// An empty file still has to POST one zero-length chunk to get a completion
		// handle back; its MAC is dropped below so the key matches MEGA's.
		chunks = []chunkSize{{position: 0, size: 0}}
	}
	fmt.Printf("Uploading %s (%d bytes)\n", displayPath, size)
	completion, macs, err := uploadChunks(ctx, f, upRes[0].P, ukey, chunks, size, uploadWorkers, postUploadChunk)
	if err != nil {
		return uploadResult{}, err
	}
	afterUpload, err := f.Stat()
	if err != nil {
		return uploadResult{}, err
	}
	if afterUpload.Size() != st.Size() || !afterUpload.ModTime().Equal(st.ModTime()) {
		return uploadResult{}, fmt.Errorf("source file changed during upload: %s", filePath)
	}
	fmt.Println()
	if completion == "" {
		return uploadResult{}, errors.New("upload server did not return a completion handle")
	}

	if size == 0 {
		// MEGA condenses no chunk MACs at all for an empty file, giving meta-MAC [0, 0].
		macs = nil
	}
	fileKey, err := buildFileKey(ukey, macs)
	if err != nil {
		return uploadResult{}, err
	}
	attr, err := encryptAttr(map[string]any{"n": remoteName}, fileKey)
	if err != nil {
		return uploadResult{}, err
	}
	node := map[string]any{
		"t": 0,
		"h": completion,
		"a": attr,
		"k": b64Encode(wordsToBytes(fileKey)),
	}
	var xpRes []struct {
		F []struct {
			H string `json:"h"`
		} `json:"f"`
	}
	if err := api.callOnce(ctx, []map[string]any{{"a": "xp", "v": 3, "t": root, "n": []map[string]any{node}}}, nil, &xpRes); err != nil {
		return uploadResult{}, err
	}
	if len(xpRes) != 1 || len(xpRes[0].F) != 1 {
		return uploadResult{}, fmt.Errorf("unexpected xp response: %+v", xpRes)
	}
	return uploadResult{Handle: xpRes[0].F[0].H, Name: remoteName, Path: displayPath, Size: size}, nil
}

type uploadChunkPoster func(ctx context.Context, uploadURL string, offset int64, data []byte) ([]byte, error)

type uploadChunkResult struct {
	index int
	size  int
	body  []byte
	mac   [aes.BlockSize]byte
	err   error
}

type chunkWorkerBuffers struct {
	plain      []byte
	enc        []byte
	macScratch [4096]byte
}

func newChunkWorkerBuffers(maxSize int) *chunkWorkerBuffers {
	return &chunkWorkerBuffers{
		plain: make([]byte, maxSize),
		enc:   make([]byte, maxSize),
	}
}

func uploadChunks(parent context.Context, r io.ReaderAt, uploadURL string, ukey []uint32, chunks []chunkSize, total int64, workers int, poster uploadChunkPoster) (string, [][]byte, error) {
	if len(chunks) == 0 {
		return "", nil, nil
	}
	if len(ukey) < 6 {
		return "", nil, fmt.Errorf("upload key is too short: %d words", len(ukey))
	}
	if workers < 1 {
		workers = 1
	}
	block, err := aes.NewCipher(wordsToBytes(ukey[:4]))
	if err != nil {
		return "", nil, err
	}
	var macIV [aes.BlockSize]byte
	putWords(macIV[:], []uint32{ukey[4], ukey[5], ukey[4], ukey[5]})

	maxChunk := 0
	for _, ch := range chunks {
		if ch.size > maxChunk {
			maxChunk = ch.size
		}
	}

	macBacking := make([]byte, len(chunks)*aes.BlockSize)
	macs := make([][]byte, len(chunks))
	for i := range macs {
		macs[i] = macBacking[i*aes.BlockSize : (i+1)*aes.BlockSize]
	}
	completion := ""
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	start := time.Now()
	var uploaded int64
	nextPrint := start
	reportProgress := func(size int) {
		uploaded += int64(size)
		if time.Now().After(nextPrint) || uploaded == total {
			printProgress(uploaded, total, start)
			nextPrint = time.Now().Add(time.Second)
		}
	}

	last := len(chunks) - 1
	if workers == 1 || last == 0 {
		bufs := newChunkWorkerBuffers(maxChunk)
		for index := 0; index <= last; index++ {
			res := uploadOneChunk(ctx, r, uploadURL, block, ukey, macIV[:], chunks[index], index, bufs, poster)
			if res.err != nil {
				return "", nil, fmt.Errorf("upload chunk at offset %d: %w", chunks[res.index].position, res.err)
			}
			copy(macs[res.index], res.mac[:])
			if index == last && len(res.body) > 0 {
				completion = string(res.body)
			}
			reportProgress(res.size)
		}
		return completion, macs, nil
	}

	workerCount := min(workers, last)
	workerBufs := make([]chunkWorkerBuffers, workerCount)
	for i := range workerBufs {
		workerBufs[i].plain = make([]byte, maxChunk)
		workerBufs[i].enc = make([]byte, maxChunk)
	}
	jobs := make(chan int)
	results := make(chan uploadChunkResult, workerCount)
	var wg sync.WaitGroup
	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		bufs := &workerBufs[i]
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case index, ok := <-jobs:
					if !ok {
						return
					}
					if ctx.Err() != nil {
						return
					}
					res := uploadOneChunk(ctx, r, uploadURL, block, ukey, macIV[:], chunks[index], index, bufs, poster)
					if res.err != nil {
						cancel()
						results <- res
						return
					}
					select {
					case results <- res:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := 0; index < last; index++ {
			select {
			case jobs <- index:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	var firstErr error
	for res := range results {
		if res.err != nil {
			// Prefer the failure that triggered cancel() over the context.Canceled
			// that every sibling worker reports afterwards.
			if firstErr == nil || (errors.Is(firstErr, context.Canceled) && !errors.Is(res.err, context.Canceled)) {
				firstErr = fmt.Errorf("upload chunk at offset %d: %w", chunks[res.index].position, res.err)
			}
			continue
		}
		copy(macs[res.index], res.mac[:])
		reportProgress(res.size)
	}
	if firstErr != nil {
		return "", nil, firstErr
	}

	res := uploadOneChunk(ctx, r, uploadURL, block, ukey, macIV[:], chunks[last], last, &workerBufs[0], poster)
	if res.err != nil {
		return "", nil, fmt.Errorf("upload chunk at offset %d: %w", chunks[res.index].position, res.err)
	}
	copy(macs[res.index], res.mac[:])
	if len(res.body) > 0 {
		completion = string(res.body)
	}
	reportProgress(res.size)
	return completion, macs, nil
}

func uploadOneChunk(ctx context.Context, r io.ReaderAt, uploadURL string, block cipher.Block, ukey []uint32, macIV []byte, ch chunkSize, index int, bufs *chunkWorkerBuffers, poster uploadChunkPoster) uploadChunkResult {
	res := uploadChunkResult{index: index, size: ch.size}
	plain := bufs.plain[:ch.size]
	enc := bufs.enc[:ch.size]
	if ch.size > 0 {
		if _, err := r.ReadAt(plain, ch.position); err != nil {
			res.err = err
			return res
		}
	}
	res.mac = encryptChunkInto(block, ukey, macIV, plain, enc, bufs.macScratch[:], ch.position)
	body, err := poster(ctx, uploadURL, ch.position, enc)
	if err != nil {
		res.err = err
		return res
	}
	res.body = body
	return res
}

type transferOptions struct {
	Title    string
	Message  string
	From     string
	Password string
	Expire   int
}

func setTransferOptions(ctx context.Context, api *apiClient, xh string, opt transferOptions) error {
	req := map[string]any{"a": "xm", "xh": xh}
	if opt.Title != "" {
		req["t"] = b64Encode([]byte(opt.Title))
	}
	if opt.Message != "" {
		req["m"] = b64Encode([]byte(opt.Message))
	}
	if opt.From != "" {
		req["se"] = opt.From
	}
	if opt.Password != "" {
		token, err := deriveTransferPassword(xh, opt.Password)
		if err != nil {
			return err
		}
		req["pw"] = token
	}
	if opt.Expire > 0 {
		req["e"] = opt.Expire * 86400
	}
	var res []json.RawMessage
	if err := api.call(ctx, []map[string]any{req}, nil, &res); err != nil {
		return err
	}
	if len(res) != 1 || string(res[0]) != "0" {
		return fmt.Errorf("xm failed: %s", rawList(res))
	}
	return nil
}

func setTransferRecipient(ctx context.Context, api *apiClient, xh, email string, schedule int64) error {
	if schedule < 0 {
		schedule = 0
	}
	req := map[string]any{"a": "xr", "xh": xh, "e": email, "s": schedule}
	var res []json.RawMessage
	if err := api.call(ctx, []map[string]any{req}, nil, &res); err != nil {
		return err
	}
	if len(res) != 1 {
		return fmt.Errorf("xr failed for %s: %s", email, rawList(res))
	}
	return nil
}

func closeTransfer(ctx context.Context, api *apiClient, xh string) error {
	var res []json.RawMessage
	if err := api.call(ctx, []map[string]any{{"a": "xc", "xh": xh}}, nil, &res); err != nil {
		return err
	}
	if len(res) != 1 || string(res[0]) != "0" {
		return fmt.Errorf("xc failed: %s", rawList(res))
	}
	return nil
}
