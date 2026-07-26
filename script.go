package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	megaAPI                = "https://g.api.mega.co.nz"
	origin                 = "https://transfer.it"
	maxAPIResponseSize     = 8 << 20
	maxUploadResponseSize  = 1 << 20
	responseHeaderTimeout  = 30 * time.Second
	connectionSetupTimeout = 10 * time.Second
	apiRequestTimeout      = 2 * time.Minute
	uploadChunkTimeout     = 2 * time.Minute
	downloadIdleTimeout    = 2 * time.Minute
	uploadChunkAttempts    = 5
	downloadAttempts       = 4
	maxPathDisambiguation  = 200

	hashcashPrefixSize = 4
	hashcashIterations = 262144
	hashcashChunkSize  = 48
)

// hashcashMaxAttempts bounds the proof-of-work search. Each attempt hashes a 12 MiB
// buffer (~8 ms), and a legitimate challenge resolves in well under a thousand
// attempts, so this leaves ample headroom for a server-side difficulty bump while
// capping the worst case at roughly half a minute on four cores.
var hashcashMaxAttempts = 1 << 14

var (
	// transferAPI is a var only so tests can point the download path at httptest.
	transferAPI = "https://bt7.api.mega.co.nz"

	httpClient = newHTTPClient()
	linkRE     = regexp.MustCompile("(?i)(?:^|[\\s<(\"'`])(?:https?://)?(?:www\\.)?transfer\\.it/t/([A-Za-z0-9_-]+)")

	// stdinReader is shared by every prompt: bufio reads ahead, so a per-prompt
	// reader would swallow the rest of a piped script after the first line.
	stdinReader = bufio.NewReader(os.Stdin)

	// errDownloadTransient marks failures worth retrying with the bytes already on
	// disk; errRangeRejected marks a resume the server refused, which is only
	// recoverable by restarting the file from byte zero.
	errDownloadTransient = errors.New("transient download failure")
	errRangeRejected     = errors.New("server rejected the resume range")
)

type apiClient struct {
	base string
	sid  string
	seq  uint64
}

type session struct {
	sid       string
	masterKey []uint32
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

type savedConfig struct {
	Version int          `json:"version"`
	Account savedAccount `json:"account,omitempty"`
}

type savedAccount struct {
	Email     string `json:"email,omitempty"`
	Password  string `json:"password,omitempty"`
	SID       string `json:"sid,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type transferNode struct {
	H  string `json:"h"`
	P  string `json:"p"`
	T  int    `json:"t"`
	A  string `json:"a"`
	K  string `json:"k"`
	S  int64  `json:"s,omitempty"`
	TS int64  `json:"ts,omitempty"`

	Name string
	Path string
}

type transferInfo struct {
	Password int     `json:"pw,omitempty"`
	Title    string  `json:"t,omitempty"`
	Message  string  `json:"m,omitempty"`
	Z        string  `json:"z,omitempty"`
	ZP       int64   `json:"zp,omitempty"`
	Size     []int64 `json:"size,omitempty"`
}

type chunkSize struct {
	position int64
	size     int
}

type uploadResult struct {
	Handle string
	Name   string
	Path   string
	Size   int64
}

type uploadItem struct {
	Source string
	Rel    string
	IsDir  bool
	Size   int64
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	var err error
	switch {
	case cmd == "download":
		err = runDownload(os.Args[2:])
	case cmd == "upload":
		err = runUpload(os.Args[2:])
	case cmd == "account":
		err = runAccount(os.Args[2:])
	// Accept a bare "transfer.it/t/HANDLE" too: parseTransferHandle already does, so
	// rejecting it here as an unknown command was an inconsistency.
	case strings.HasPrefix(cmd, "http://") || strings.HasPrefix(cmd, "https://") || linkRE.MatchString(cmd):
		err = runDownload(os.Args[1:])
	case cmd == "-h" || cmd == "--help" || cmd == "help":
		usage()
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  go run script.go <transfer.it-url> [--password PASS] [--out DIR]
  go run script.go download <transfer.it-url> [--password PASS] [--out DIR]

  go run script.go upload [options] FILE_OR_DIR [FILE_OR_DIR...]
  go run script.go account login --email EMAIL [--password PASS] [--save-password]
  go run script.go account status
  go run script.go account logout

Upload options:
  --title TEXT              transfer title; defaults to the file name or a timestamp
  --message TEXT            transfer message
  --from EMAIL              "Your email (optional)"
  --password PASS           add a password to the transfer link
  --expire DAYS             expire in 7, 30, 90, or 0 days; default 90
  --to EMAILS               comma-separated "Email to" recipients; enables Send files behavior
  --send-at TIME            scheduled send time, as Unix seconds or RFC3339
  --account                 use a saved/logged-in MEGA account session instead of a guest session
  --account-email EMAIL     MEGA account email for one-shot account login during upload
  --account-password PASS   MEGA account password for one-shot account login during upload
  --account-mfa CODE        MEGA account two-factor authentication code
  --save-account-password   save the account password when logging in during upload
  --upload-workers N        parallel upload chunk workers; default 4

Examples:
  go run script.go https://transfer.it/t/TRANSFER_HANDLE --password YOUR_LINK_PASSWORD
  go run script.go account login --email user@example.com --save-password
  go run script.go upload --title "Big test" --message "hello" --expire 7 ./file.bin
  go run script.go upload --account --title "Account upload" ./file.bin
  go run script.go upload --to a@example.com,b@example.com --from me@example.com --send-at 2026-06-01T10:30:00Z ./file.bin
`)
}

func runDownload(args []string) error {
	args = normalizeLeadingPositional(args)
	fs := flag.NewFlagSet("download", flag.ContinueOnError)
	password := fs.String("password", "", "transfer password")
	outDir := fs.String("out", ".", "output directory")
	if err := fs.Parse(args); err != nil {
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
	info, err := getTransferInfo(xh)
	if err != nil {
		return err
	}
	if info.Password != 0 {
		pass := strings.TrimSpace(*password)
		if pass == "" {
			entered, err := promptSecret("Password: ")
			if err != nil {
				return fmt.Errorf("password required: %w", err)
			}
			pass = strings.TrimSpace(entered)
		}
		pwToken, err = deriveTransferPassword(xh, pass)
		if err != nil {
			return err
		}
		if err := validateTransferPassword(xh, pwToken); err != nil {
			return err
		}
	}

	nodes, err := fetchNodes(xh, pwToken)
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

	seenPaths := map[string]reservedPath{}
	folderPaths := make([]string, 0, len(folders))
	for _, folder := range folders {
		if folder.P == "" || folder.Path == "" {
			continue
		}
		dst, err := resolveDownloadPath(baseDir, folder.Path)
		if err != nil {
			return fmt.Errorf("invalid folder path %q: %w", folder.Path, err)
		}
		if err := reserveFolderPath(seenPaths, dst, "folder "+folder.Path); err != nil {
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
		reserved, err := reserveFilePath(seenPaths, dst, "file "+rel)
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
		if err := downloadNode(downloadRoot, xh, pwToken, download.node, rel, download.dst); err != nil {
			return err
		}
	}
	return nil
}

func normalizeLeadingPositional(args []string) []string {
	if len(args) > 1 && !strings.HasPrefix(args[0], "-") {
		out := append([]string{}, args[1:]...)
		out = append(out, args[0])
		return out
	}
	return args
}

func runAccount(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		accountUsage()
		return nil
	}
	switch args[0] {
	case "login":
		return runAccountLogin(args[1:])
	case "status":
		return runAccountStatus(args[1:])
	case "logout":
		return runAccountLogout(args[1:])
	default:
		return fmt.Errorf("unknown account command %q", args[0])
	}
}

func accountUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  go run script.go account login --email EMAIL [--password PASS] [--save-password]
  go run script.go account status
  go run script.go account logout

Account options:
  --email EMAIL       MEGA account email
  --password PASS     MEGA account password; prompted if omitted
  --mfa CODE          two-factor authentication code, if the account requires it
  --save-password     save the account password in the local config file
  --no-save           validate login but do not save the session

The saved config path is:
  %s
`, mustConfigPath())
}

func runAccountLogin(args []string) error {
	fs := flag.NewFlagSet("account login", flag.ContinueOnError)
	email := fs.String("email", "", "MEGA account email")
	password := fs.String("password", "", "MEGA account password")
	mfa := fs.String("mfa", "", "MEGA two-factor code")
	savePassword := fs.Bool("save-password", false, "save account password in local config")
	noSave := fs.Bool("no-save", false, "validate login without saving anything")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("account login does not take positional arguments")
	}

	cfg, _, _ := loadSavedConfig()
	loginEmail := normalizeEmail(*email)
	if loginEmail == "" {
		loginEmail = normalizeEmail(cfg.Account.Email)
	}
	if loginEmail == "" {
		entered, err := promptLine("MEGA account email: ")
		if err != nil {
			return err
		}
		loginEmail = normalizeEmail(entered)
	}
	if loginEmail == "" {
		return errors.New("MEGA account email is required")
	}

	loginPassword := *password
	if loginPassword == "" {
		entered, err := promptSecret("MEGA account password: ")
		if err != nil {
			return err
		}
		loginPassword = entered
	}
	if loginPassword == "" {
		return errors.New("MEGA account password is required")
	}

	fmt.Printf("Logging in to MEGA account %s...\n", loginEmail)
	sess, err := loginMegaAccount(loginEmail, loginPassword, strings.TrimSpace(*mfa))
	if err != nil {
		return err
	}
	fmt.Printf("Login OK for %s.\n", loginEmail)

	if *noSave {
		return nil
	}

	passwordToStore := passwordToPersist(cfg, loginEmail, loginPassword, *savePassword, false)
	if err := saveAccountSession(loginEmail, passwordToStore, sess); err != nil {
		return err
	}
	fmt.Printf("Saved account session to %s.\n", mustConfigPath())
	if *savePassword {
		fmt.Println("Saved account password too. Protect the config file as an account credential.")
	}
	return nil
}

func runAccountStatus(args []string) error {
	fs := flag.NewFlagSet("account status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("account status does not take positional arguments")
	}

	cfg, exists, err := loadSavedConfig()
	if err != nil {
		return err
	}
	fmt.Printf("Config: %s\n", mustConfigPath())
	if !exists || cfg.Account.Email == "" {
		fmt.Println("No saved MEGA account.")
		return nil
	}
	fmt.Printf("Email: %s\n", cfg.Account.Email)
	fmt.Printf("Saved session: %t\n", cfg.Account.SID != "")
	fmt.Printf("Saved password: %t\n", cfg.Account.Password != "")
	if cfg.Account.UpdatedAt != "" {
		fmt.Printf("Updated: %s\n", cfg.Account.UpdatedAt)
	}
	return nil
}

func runAccountLogout(args []string) error {
	fs := flag.NewFlagSet("account logout", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("account logout does not take positional arguments")
	}
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Printf("Removed saved account config: %s\n", path)
	return nil
}

func resolveUploadSession(useAccount bool, accountEmail, accountPassword, mfa string, savePassword bool) (session, string, error) {
	if !useAccount {
		fmt.Println("Creating anonymous MEGA/transfer.it session...")
		sess, err := createAnonymousSession()
		return sess, "anonymous MEGA/transfer.it session", err
	}

	cfg, _, err := loadSavedConfig()
	if err != nil {
		return session{}, "", err
	}

	explicitPassword := accountPassword != ""
	email := normalizeEmail(accountEmail)
	if email == "" {
		email = normalizeEmail(cfg.Account.Email)
	}

	if !explicitPassword && cfg.Account.SID != "" && (email == "" || strings.EqualFold(email, cfg.Account.Email)) {
		label := "saved MEGA account session"
		if cfg.Account.Email != "" {
			label += " for " + cfg.Account.Email
		}
		return session{sid: cfg.Account.SID}, label, nil
	}

	password := accountPassword
	passwordFromConfig := false
	if password == "" && cfg.Account.Password != "" && (email == "" || strings.EqualFold(email, cfg.Account.Email)) {
		password = cfg.Account.Password
		passwordFromConfig = true
	}

	if password != "" {
		if email == "" {
			entered, err := promptLine("MEGA account email: ")
			if err != nil {
				return session{}, "", err
			}
			email = normalizeEmail(entered)
		}
		if email == "" {
			return session{}, "", errors.New("MEGA account email is required")
		}
		fmt.Printf("Logging in to MEGA account %s...\n", email)
		sess, err := loginMegaAccount(email, password, mfa)
		if err != nil {
			return session{}, "", err
		}

		passwordToStore := passwordToPersist(cfg, email, password, savePassword, passwordFromConfig)
		if err := saveAccountSession(email, passwordToStore, sess); err != nil {
			return session{}, "", err
		}
		return sess, "MEGA account session for " + email, nil
	}

	if email == "" {
		entered, err := promptLine("MEGA account email: ")
		if err != nil {
			return session{}, "", err
		}
		email = normalizeEmail(entered)
	}
	password, err = promptSecret("MEGA account password: ")
	if err != nil {
		return session{}, "", err
	}
	if email == "" || password == "" {
		return session{}, "", errors.New("MEGA account email and password are required")
	}

	fmt.Printf("Logging in to MEGA account %s...\n", email)
	sess, err := loginMegaAccount(email, password, mfa)
	if err != nil {
		return session{}, "", err
	}
	passwordToStore := passwordToPersist(cfg, email, password, savePassword, false)
	if err := saveAccountSession(email, passwordToStore, sess); err != nil {
		return session{}, "", err
	}
	return sess, "MEGA account session for " + email, nil
}

func refreshAccountSession(accountEmail, accountPassword, mfa string, savePassword bool) (session, string, error) {
	cfg, _, err := loadSavedConfig()
	if err != nil {
		return session{}, "", err
	}
	email := normalizeEmail(accountEmail)
	if email == "" {
		email = normalizeEmail(cfg.Account.Email)
	}
	if email == "" {
		entered, err := promptLine("MEGA account email: ")
		if err != nil {
			return session{}, "", err
		}
		email = normalizeEmail(entered)
	}
	password := accountPassword
	passwordFromConfig := false
	if password == "" && cfg.Account.Password != "" && strings.EqualFold(email, cfg.Account.Email) {
		password = cfg.Account.Password
		passwordFromConfig = true
	}
	if password == "" {
		entered, err := promptSecret("MEGA account password: ")
		if err != nil {
			return session{}, "", err
		}
		password = entered
	}
	if email == "" || password == "" {
		return session{}, "", errors.New("MEGA account email and password are required to refresh the account session")
	}

	fmt.Printf("Logging in to MEGA account %s...\n", email)
	sess, err := loginMegaAccount(email, password, mfa)
	if err != nil {
		return session{}, "", err
	}
	passwordToStore := passwordToPersist(cfg, email, password, savePassword, passwordFromConfig)
	if err := saveAccountSession(email, passwordToStore, sess); err != nil {
		return session{}, "", err
	}
	return sess, "refreshed MEGA account session for " + email, nil
}

func runUpload(args []string) error {
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
	if err := fs.Parse(args); err != nil {
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

	sess, sessionLabel, err := resolveUploadSession(*useAccount, strings.TrimSpace(*accountEmail), *accountPassword, strings.TrimSpace(*accountMFA), *saveAccountPassword)
	if err != nil {
		return err
	}
	fmt.Printf("Using %s.\n", sessionLabel)
	tapi := &apiClient{base: transferAPI, sid: sess.sid}

	root, xh, err := createTransfer(tapi, name)
	if err != nil && *useAccount && isInvalidSessionError(err) {
		fmt.Println("Saved account session was rejected; refreshing MEGA login...")
		sess, sessionLabel, err = refreshAccountSession(strings.TrimSpace(*accountEmail), *accountPassword, strings.TrimSpace(*accountMFA), *saveAccountPassword)
		if err != nil {
			return err
		}
		fmt.Printf("Using %s.\n", sessionLabel)
		tapi = &apiClient{base: transferAPI, sid: sess.sid}
		root, xh, err = createTransfer(tapi, name)
	}
	if err != nil {
		return err
	}
	fmt.Printf("Transfer created: https://transfer.it/t/%s\n", xh)

	folderHandles, err := createRemoteFolders(tapi, root, items)
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
		res, err := uploadFile(tapi, parent, item.Source, pathpkg.Base(item.Rel), item.Rel, *uploadWorkers)
		if err != nil {
			return err
		}
		results = append(results, res)
	}

	if err := setTransferOptions(tapi, xh, transferOptions{
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
			if err := setTransferRecipient(tapi, xh, email, schedule); err != nil {
				return err
			}
		}
	}

	if err := closeTransfer(tapi, xh); err != nil {
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

func getTransferInfo(xh string) (transferInfo, error) {
	var out []transferInfo
	err := (&apiClient{base: transferAPI}).call([]map[string]any{{"a": "xi", "xh": xh}}, nil, &out)
	if err != nil {
		return transferInfo{}, err
	}
	if len(out) != 1 {
		return transferInfo{}, errors.New("unexpected xi response")
	}
	return out[0], nil
}

func validateTransferPassword(xh, token string) error {
	var out []json.RawMessage
	err := (&apiClient{base: transferAPI}).call([]map[string]any{{"a": "xv", "xh": xh, "pw": token}}, nil, &out)
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

func fetchNodes(xh, pwToken string) ([]transferNode, error) {
	q := url.Values{"x": {xh}}
	if pwToken != "" {
		q.Set("pw", pwToken)
	}
	var raw json.RawMessage
	err := (&apiClient{base: transferAPI}).call([]map[string]any{{"a": "f", "c": 1, "r": 1}}, q, &raw)
	if err != nil {
		return nil, err
	}
	if len(raw) > 0 && raw[0] == '-' {
		return nil, fmt.Errorf("node fetch failed with API code %s", raw)
	}
	var out []struct {
		F []transferNode `json:"f"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if len(out) != 1 {
		return nil, errors.New("unexpected f response")
	}
	nodes := out[0].F
	byHandle := map[string]*transferNode{}
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
		parts = append([]string{safeName(parent.Name)}, parts...)
		p = parent.P
	}
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

// reserveFolderPath claims dst for a directory. Directories merge on collision:
// renaming one would be unsound because buildNodePath derives child paths
// independently and would not follow the rename. Real conflicts between their
// contents are caught later by reserveFilePath.
func reserveFolderPath(seen map[string]reservedPath, dst, label string) error {
	key := portableDownloadPathKey(dst)
	if prev, ok := seen[key]; ok {
		if !prev.isDir {
			return fmt.Errorf("download path collision: %s and %s both map to %s", prev.label, label, filepath.Clean(dst))
		}
		return nil
	}
	seen[key] = reservedPath{label: label, isDir: true}
	return nil
}

// reserveFilePath claims dst and its .part sidecar for a file, appending " (n)" to
// the stem until both are free. Disambiguating keeps the rest of the transfer
// downloadable instead of failing the whole run over one collision, while still
// guaranteeing no two nodes ever write to the same local file.
func reserveFilePath(seen map[string]reservedPath, dst, label string) (string, error) {
	dir, base := filepath.Split(dst)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	candidate := dst
	for n := 1; ; n++ {
		key := portableDownloadPathKey(candidate)
		partKey := portableDownloadPathKey(candidate + ".part")
		prev, taken := seen[key]
		prevPart, partTaken := seen[partKey]
		if !taken && !partTaken {
			seen[key] = reservedPath{label: label}
			seen[partKey] = reservedPath{label: "partial " + label}
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
		candidate = filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, n, ext))
	}
}

func portableDownloadPathKey(path string) string {
	volume := strings.ToLower(filepath.VolumeName(path))
	path = strings.TrimPrefix(filepath.Clean(path), filepath.VolumeName(path))
	parts := strings.FieldsFunc(filepath.ToSlash(path), func(r rune) bool { return r == '/' })
	for i := range parts {
		parts[i] = cases.Fold().String(norm.NFC.String(strings.TrimRight(parts[i], " .")))
	}
	return volume + "/" + strings.Join(parts, "/")
}

func downloadNode(root *os.Root, xh, pwToken string, n transferNode, rel, displayPath string) error {
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

	if err := downloadNodeWithRetry(root, xh, pwToken, n, partRel, displayPath+".part", existing); err != nil {
		return err
	}
	if err := verifyDownloadedFileInRoot(root, partRel, n); err != nil {
		if existing > 0 {
			fmt.Printf("Integrity check failed after resume, retrying from start: %v\n", err)
			if err := downloadNodeWithRetry(root, xh, pwToken, n, partRel, displayPath+".part", 0); err != nil {
				return err
			}
			if retryErr := verifyDownloadedFileInRoot(root, partRel, n); retryErr != nil {
				return fmt.Errorf("downloaded file failed integrity check after retry: %w", retryErr)
			}
		} else {
			return fmt.Errorf("downloaded file failed integrity check: %w", err)
		}
	}
	return root.Rename(partRel, rel)
}

// downloadNodeWithRetry fetches a node into its .part file, absorbing transient
// network failures instead of aborting every remaining file in the transfer. Each
// attempt re-measures what actually landed on disk and resumes from there; only a
// resume the server explicitly refuses restarts from byte zero, because
// downloadNodeBytes truncates when existing == 0.
func downloadNodeWithRetry(root *os.Root, xh, pwToken string, n transferNode, rel, displayPath string, existing int64) error {
	var lastErr error
	for attempt := 0; attempt < downloadAttempts; attempt++ {
		err := downloadNodeBytes(root, xh, pwToken, n, rel, displayPath, existing)
		if err == nil {
			return nil
		}
		lastErr = err
		switch {
		case errors.Is(err, errRangeRejected) && existing > 0:
			fmt.Printf("Server refused to resume %s, restarting from the beginning: %v\n", displayPath, err)
			existing = 0
		case errors.Is(err, errDownloadTransient) && attempt < downloadAttempts-1:
			time.Sleep(apiRetryDelay(attempt))
			existing = 0
			if st, statErr := root.Lstat(rel); statErr == nil && st.Mode().IsRegular() && st.Size() <= n.S {
				existing = st.Size()
			}
			fmt.Printf("Download of %s failed (%v); retrying from %d bytes\n", displayPath, err, existing)
		default:
			return err
		}
	}
	return lastErr
}

func downloadNodeBytes(root *os.Root, xh, pwToken string, n transferNode, rel, displayPath string, existing int64) error {
	downloadURL := fmt.Sprintf("%s/cs/g?x=%s&n=%s&fn=%s", transferAPI, url.QueryEscape(xh), url.QueryEscape(n.H), url.QueryEscape(n.Name))
	if pwToken != "" {
		downloadURL += "&pw=" + url.QueryEscape(pwToken)
	}

	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Referer", origin+"/t/"+xh)
	req.Header.Set("Origin", origin)
	if existing > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", existing))
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", errDownloadTransient, sanitizeHTTPError(err, req.URL))
	}
	defer resp.Body.Close()
	if existing > 0 && resp.StatusCode == http.StatusOK {
		existing = 0
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		body, _ := io.ReadAll(io.LimitReader(idleTimeoutReader{reader: resp.Body, timeout: downloadIdleTimeout}, 4096))
		statusErr := fmt.Errorf("download HTTP %s: %s", resp.Status, strings.TrimSpace(string(body)))
		switch {
		case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
			return fmt.Errorf("%w: %w", errRangeRejected, statusErr)
		case isTransientHTTPStatus(resp.StatusCode):
			return fmt.Errorf("%w: %w", errDownloadTransient, statusErr)
		}
		return statusErr
	}
	if resp.StatusCode == http.StatusPartialContent {
		if existing == 0 {
			return errors.New("download server returned an unexpected partial response")
		}
		if err := validateContentRange(resp.Header.Get("Content-Range"), existing, n.S); err != nil {
			return fmt.Errorf("%w: %w", errRangeRejected, err)
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
		return err
	}
	fmt.Printf("Downloading %s -> %s\n", n.Name, displayPath)
	remaining := n.S - existing
	limited := &io.LimitedReader{R: idleTimeoutReader{reader: resp.Body, timeout: downloadIdleTimeout}, N: remaining + 1}
	copyErr := copyWithProgress(f, limited, existing, n.S)
	closeErr := f.Close()
	if copyErr != nil {
		// A reset or stall mid-body is retryable; the bytes already flushed stay put.
		return fmt.Errorf("%w: %w", errDownloadTransient, copyErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if limited.N == 0 {
		return fmt.Errorf("download exceeded expected size of %d bytes", n.S)
	}
	st, err := root.Stat(rel)
	if err != nil {
		return err
	}
	if st.Size() != n.S {
		return fmt.Errorf("%w: download ended at %d bytes, want %d", errDownloadTransient, st.Size(), n.S)
	}
	return nil
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

type idleTimeoutReader struct {
	reader  io.Reader
	timeout time.Duration
}

func (r idleTimeoutReader) Read(p []byte) (int, error) {
	type result struct {
		n   int
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		n, err := r.reader.Read(p)
		resultCh <- result{n: n, err: err}
	}()
	timer := time.NewTimer(r.timeout)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		return result.n, result.err
	case <-timer.C:
		return 0, fmt.Errorf("%w: download stalled for %s", errDownloadTransient, r.timeout)
	}
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
	computed, err := computeFileKeyFromReader(f, fileKey, n.S)
	if err != nil {
		return err
	}
	if !wordsEqual(computed, fileKey) {
		return errors.New("MAC mismatch")
	}
	return nil
}

func decodeFileKey(key64 string) ([]uint32, error) {
	keyBytes, err := b64Decode(key64)
	if err != nil {
		return nil, err
	}
	if len(keyBytes)%4 != 0 {
		return nil, fmt.Errorf("file key is not word-aligned: %d bytes", len(keyBytes))
	}
	keyWords := bytesToWords(keyBytes)
	if len(keyWords) < 8 {
		return nil, fmt.Errorf("file key is too short: %d words", len(keyWords))
	}
	return keyWords[:8], nil
}

func computeFileKeyFromReader(f io.ReaderAt, fileKey []uint32, size int64) ([]uint32, error) {
	if len(fileKey) < 8 {
		return nil, fmt.Errorf("file key is too short: %d words", len(fileKey))
	}
	ukey := []uint32{
		fileKey[0] ^ fileKey[4],
		fileKey[1] ^ fileKey[5],
		fileKey[2] ^ fileKey[6],
		fileKey[3] ^ fileKey[7],
		fileKey[4],
		fileKey[5],
	}
	// A zero-length file has no chunks at all, so its meta-MAC condenses to [0, 0].
	// Feeding buildFileKey a synthetic empty chunk would instead yield AES(k, 0) and
	// disagree with every other MEGA client.
	macs, err := chunkMACs(f, ukey, getChunkSizes(size))
	if err != nil {
		return nil, err
	}
	return buildFileKey(ukey, macs)
}

// chunkMACs is the read-only counterpart to encryptUploadChunk: it produces the same
// per-chunk CBC-MACs without the AES-CTR pass or the per-chunk allocations, which is
// all the download verification path needs.
func chunkMACs(f io.ReaderAt, ukey []uint32, chunks []chunkSize) ([][]byte, error) {
	if len(chunks) == 0 {
		return nil, nil
	}
	if len(ukey) < 6 {
		return nil, fmt.Errorf("upload key is too short: %d words", len(ukey))
	}
	block, err := aes.NewCipher(wordsToBytes(ukey[:4]))
	if err != nil {
		return nil, err
	}
	iv := wordsToBytes([]uint32{ukey[4], ukey[5], ukey[4], ukey[5]})
	largest := 0
	for _, ch := range chunks {
		if ch.size > largest {
			largest = ch.size
		}
	}
	scratch := make([]byte, largest+aes.BlockSize)
	macs := make([][]byte, 0, len(chunks))
	for _, ch := range chunks {
		mac := make([]byte, aes.BlockSize)
		if ch.size > 0 {
			padded := scratch[:paddedLen(ch.size, aes.BlockSize)]
			if _, err := f.ReadAt(padded[:ch.size], ch.position); err != nil {
				return nil, err
			}
			// scratch still holds the previous chunk, so the null padding must be
			// re-zeroed or a short trailing chunk MACs stale bytes.
			clear(padded[ch.size:])
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(padded, padded)
			copy(mac, padded[len(padded)-aes.BlockSize:])
		}
		macs = append(macs, mac)
	}
	return macs, nil
}

func paddedLen(n, blockSize int) int {
	if rem := n % blockSize; rem != 0 {
		return n + blockSize - rem
	}
	return n
}

func createAnonymousSession() (session, error) {
	masterKey, err := randomWords(4)
	if err != nil {
		return session{}, err
	}
	passwordKey, err := randomWords(4)
	if err != nil {
		return session{}, err
	}
	ssc, err := randomWords(4)
	if err != nil {
		return session{}, err
	}
	encryptedMaster, err := encryptWords(passwordKey, masterKey)
	if err != nil {
		return session{}, err
	}
	encryptedSSC, err := encryptWords(masterKey, ssc)
	if err != nil {
		return session{}, err
	}
	upReq := []map[string]any{{
		"a":  "up",
		"k":  b64Encode(wordsToBytes(encryptedMaster)),
		"ts": b64Encode(append(wordsToBytes(ssc), wordsToBytes(encryptedSSC)...)),
	}}
	var upRes []string
	if err := (&apiClient{base: megaAPI}).call(upReq, nil, &upRes); err != nil {
		return session{}, err
	}
	if len(upRes) != 1 {
		return session{}, errors.New("unexpected up response")
	}

	var usRes []struct {
		TSID string `json:"tsid"`
		Key  string `json:"k"`
	}
	if err := (&apiClient{base: megaAPI}).call([]map[string]any{{"a": "us", "user": upRes[0]}}, nil, &usRes); err != nil {
		return session{}, err
	}
	if len(usRes) != 1 {
		return session{}, errors.New("unexpected us response")
	}
	encKeyBytes, err := b64Decode(usRes[0].Key)
	if err != nil {
		return session{}, err
	}
	decMaster, err := decryptWords(passwordKey, bytesToWords(encKeyBytes))
	if err != nil {
		return session{}, err
	}
	sid, err := sidFromTSID(usRes[0].TSID, decMaster)
	if err != nil {
		return session{}, err
	}
	return session{sid: sid, masterKey: decMaster}, nil
}

type megaLoginMethod struct {
	Version int    `json:"v"`
	Salt    string `json:"s"`
}

type megaLoginResponse struct {
	Key   string `json:"k"`
	CSID  string `json:"csid"`
	PrivK string `json:"privk"`
	TSID  string `json:"tsid"`
	MFAE  int    `json:"mfae,omitempty"`
}

func loginMegaAccount(email, password, mfa string) (session, error) {
	email = normalizeEmail(email)
	if email == "" {
		return session{}, errors.New("MEGA account email is required")
	}
	if password == "" {
		return session{}, errors.New("MEGA account password is required")
	}

	method, err := getMegaLoginMethod(email)
	if err != nil {
		return session{}, err
	}

	var passwordKey []uint32
	var userHash string
	switch method.Version {
	case 2:
		passwordKey, userHash, err = deriveMegaV2Login(password, method.Salt)
	default:
		passwordKey, userHash, err = deriveMegaV1Login(email, password)
	}
	if err != nil {
		return session{}, err
	}
	return completeMegaLogin(email, userHash, passwordKey, mfa)
}

func getMegaLoginMethod(email string) (megaLoginMethod, error) {
	var raw []json.RawMessage
	err := (&apiClient{base: megaAPI}).call([]map[string]any{{"a": "us0", "user": email}}, nil, &raw)
	if err != nil {
		return megaLoginMethod{}, err
	}
	if len(raw) != 1 {
		return megaLoginMethod{}, errors.New("unexpected us0 response")
	}
	if isNegativeJSON(raw[0]) {
		return megaLoginMethod{}, fmt.Errorf("MEGA login method failed with API code %s", strings.TrimSpace(string(raw[0])))
	}
	var method megaLoginMethod
	if err := json.Unmarshal(raw[0], &method); err != nil {
		return megaLoginMethod{}, err
	}
	if method.Version == 0 {
		method.Version = 1
	}
	return method, nil
}

func completeMegaLogin(email, userHash string, passwordKey []uint32, mfa string) (session, error) {
	req := map[string]any{"a": "us", "user": email, "uh": userHash}
	if mfa != "" {
		req["mfa"] = mfa
	}
	var raw []json.RawMessage
	err := (&apiClient{base: megaAPI}).call([]map[string]any{req}, nil, &raw)
	if err != nil {
		var apiErr apiError
		if errors.As(err, &apiErr) && apiErr.Code == -26 {
			return session{}, errors.New("MEGA account requires two-factor authentication; pass --mfa CODE")
		}
		return session{}, err
	}
	if len(raw) != 1 {
		return session{}, errors.New("unexpected us response")
	}
	if isNegativeJSON(raw[0]) {
		code := strings.TrimSpace(string(raw[0]))
		if code == "-26" {
			return session{}, errors.New("MEGA account requires two-factor authentication; pass --mfa CODE")
		}
		return session{}, fmt.Errorf("MEGA login failed with API code %s", code)
	}

	var res megaLoginResponse
	if err := json.Unmarshal(raw[0], &res); err != nil {
		return session{}, err
	}
	if res.Key == "" {
		if res.MFAE != 0 {
			return session{}, errors.New("MEGA account requires two-factor authentication; pass --mfa CODE")
		}
		return session{}, fmt.Errorf("MEGA login response did not include an encrypted master key: %s", string(raw[0]))
	}

	encKeyBytes, err := b64Decode(res.Key)
	if err != nil {
		return session{}, err
	}
	if len(encKeyBytes)%aes.BlockSize != 0 {
		return session{}, fmt.Errorf("encrypted master key is not AES-aligned: %d bytes", len(encKeyBytes))
	}
	masterKey, err := decryptWords(passwordKey, bytesToWords(encKeyBytes))
	if err != nil {
		return session{}, err
	}
	if len(masterKey) < 4 {
		return session{}, errors.New("decrypted master key is too short")
	}
	masterKey = masterKey[:4]

	if res.TSID != "" {
		sid, err := sidFromTSID(res.TSID, masterKey)
		if err != nil {
			return session{}, err
		}
		return session{sid: sid, masterKey: masterKey}, nil
	}

	if res.CSID == "" || res.PrivK == "" {
		return session{}, errors.New("MEGA login response did not include csid/privk session material")
	}
	sid, err := sidFromCSID(res.CSID, res.PrivK, masterKey)
	if err != nil {
		return session{}, err
	}
	return session{sid: sid, masterKey: masterKey}, nil
}

func deriveMegaV2Login(password, salt64 string) ([]uint32, string, error) {
	if salt64 == "" {
		return nil, "", errors.New("MEGA login v2 response did not include a salt")
	}
	salt, err := b64Decode(salt64)
	if err != nil {
		return nil, "", err
	}
	key, err := pbkdf2.Key(sha512.New, password, salt, 100000, 32)
	if err != nil {
		return nil, "", err
	}
	return bytesToWords(key[:16]), b64Encode(key[16:]), nil
}

func deriveMegaV1Login(email, password string) ([]uint32, string, error) {
	passwordKey, err := prepareMegaKey(stringToWords(password))
	if err != nil {
		return nil, "", err
	}
	userHash, err := megaStringHash(normalizeEmail(email), passwordKey)
	if err != nil {
		return nil, "", err
	}
	return passwordKey, userHash, nil
}

func prepareMegaKey(words []uint32) ([]uint32, error) {
	if len(words) == 0 {
		words = []uint32{0, 0, 0, 0}
	}
	blocks := make([]cipher.Block, 0, (len(words)+3)/4)
	for i := 0; i < len(words); i += 4 {
		var blockKey [4]uint32
		copy(blockKey[:], words[i:minInt(i+4, len(words))])
		block, err := aes.NewCipher(wordsToBytes(blockKey[:]))
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}
	key := wordsToBytes([]uint32{0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56})
	for round := 0; round < 0x10000; round++ {
		for _, block := range blocks {
			block.Encrypt(key, key)
		}
	}
	return bytesToWords(key), nil
}

func megaStringHash(email string, passwordKey []uint32) (string, error) {
	words := stringToWords(strings.ToLower(email))
	hashWords := []uint32{0, 0, 0, 0}
	for i, word := range words {
		hashWords[i%4] ^= word
	}
	block, err := aes.NewCipher(wordsToBytes(passwordKey))
	if err != nil {
		return "", err
	}
	hashBytes := wordsToBytes(hashWords)
	for i := 0; i < 0x4000; i++ {
		block.Encrypt(hashBytes, hashBytes)
	}
	hashWords = bytesToWords(hashBytes)
	return b64Encode(wordsToBytes([]uint32{hashWords[0], hashWords[2]})), nil
}

func sidFromTSID(tsid64 string, masterKey []uint32) (string, error) {
	tsid, err := b64Decode(tsid64)
	if err != nil {
		return "", err
	}
	if len(tsid) != 43 {
		return "", fmt.Errorf("unexpected tsid length %d", len(tsid))
	}
	check, err := encryptWords(masterKey, bytesToWords(tsid[:16]))
	if err != nil {
		return "", err
	}
	if !bytes.Equal(wordsToBytes(check), tsid[27:43]) {
		return "", errors.New("session self-check failed")
	}
	return b64Encode(tsid), nil
}

func sidFromCSID(csid64, privk64 string, masterKey []uint32) (string, error) {
	privBytes, err := b64Decode(privk64)
	if err != nil {
		return "", err
	}
	if len(privBytes)%aes.BlockSize != 0 {
		return "", fmt.Errorf("encrypted private key is not AES-aligned: %d bytes", len(privBytes))
	}
	privWords, err := decryptWords(masterKey, bytesToWords(privBytes))
	if err != nil {
		return "", err
	}
	privPlain := wordsToBytes(privWords)
	pos := 0
	p, next, err := readMPI(privPlain, pos)
	if err != nil {
		return "", fmt.Errorf("could not read RSA p: %w", err)
	}
	pos = next
	q, next, err := readMPI(privPlain, pos)
	if err != nil {
		return "", fmt.Errorf("could not read RSA q: %w", err)
	}
	pos = next
	d, _, err := readMPI(privPlain, pos)
	if err != nil {
		return "", fmt.Errorf("could not read RSA d: %w", err)
	}

	csidBytes, err := b64Decode(csid64)
	if err != nil {
		return "", err
	}
	encryptedSID, _, err := readMPI(csidBytes, 0)
	if err != nil {
		encryptedSID = new(big.Int).SetBytes(csidBytes)
	}
	// readMPI happily returns zero for a zero-length MPI, and big.Int.Exp treats a
	// zero modulus as "no modular reduction" — an exact integer power with an
	// exponent up to 2^65535 that would hang the process until it is OOM-killed.
	modulus := new(big.Int).Mul(p, q)
	if modulus.BitLen() < 512 || d.BitLen() > modulus.BitLen() {
		return "", errors.New("invalid RSA private key material in login response")
	}
	plainSID := new(big.Int).Exp(encryptedSID, d, modulus).Bytes()
	if len(plainSID) < 43 {
		return "", fmt.Errorf("decrypted account session id is too short: %d bytes", len(plainSID))
	}
	return b64Encode(plainSID[:43]), nil
}

func createTransfer(api *apiClient, title string) (root, xh string, err error) {
	key, err := randomWords(4)
	if err != nil {
		return "", "", err
	}
	attr, err := encryptAttr(map[string]any{"t": time.Now().Unix(), "n": title}, key)
	if err != nil {
		return "", "", err
	}
	var res [][]string
	err = api.call([]map[string]any{{"a": "xn", "at": attr, "k": b64Encode(wordsToBytes(key))}}, nil, &res)
	if err != nil {
		return "", "", err
	}
	if len(res) != 1 || len(res[0]) != 2 {
		return "", "", fmt.Errorf("unexpected xn response: %+v", res)
	}
	xh, root = res[0][0], res[0][1]
	return root, xh, nil
}

func createRemoteFolders(api *apiClient, root string, items []uploadItem) (map[string]string, error) {
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
		handle, err := createRemoteFolder(api, parent, pathpkg.Base(item.Rel))
		if err != nil {
			return nil, err
		}
		handles[item.Rel] = handle
		fmt.Printf("Created folder: %s\n", item.Rel)
	}
	return handles, nil
}

func createRemoteFolder(api *apiClient, parent, name string) (string, error) {
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
	if err := api.call([]map[string]any{{"a": "xp", "v": 3, "t": parent, "n": []map[string]any{node}}}, nil, &xpRes); err != nil {
		return "", err
	}
	if len(xpRes) != 1 || len(xpRes[0].F) != 1 || xpRes[0].F[0].H == "" {
		return "", fmt.Errorf("unexpected folder xp response: %+v", xpRes)
	}
	return xpRes[0].F[0].H, nil
}

func uploadFile(api *apiClient, root, filePath, remoteName, displayPath string, uploadWorkers int) (uploadResult, error) {
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
	if err := api.call([]map[string]any{{"a": "u", "s": size, "ssl": 2}}, nil, &upRes); err != nil {
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
	completion, macs, err := uploadChunks(f, upRes[0].P, ukey, chunks, size, uploadWorkers, postUploadChunk)
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
	if err := api.call([]map[string]any{{"a": "xp", "v": 3, "t": root, "n": []map[string]any{node}}}, nil, &xpRes); err != nil {
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
	mac   []byte
	err   error
}

func uploadChunks(r io.ReaderAt, uploadURL string, ukey []uint32, chunks []chunkSize, total int64, workers int, poster uploadChunkPoster) (string, [][]byte, error) {
	if len(chunks) == 0 {
		return "", nil, nil
	}
	if workers < 1 {
		workers = 1
	}
	macs := make([][]byte, len(chunks))
	completion := ""
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	var uploaded int64
	nextPrint := time.Now()
	reportProgress := func(size int) {
		uploaded += int64(size)
		if time.Now().After(nextPrint) || uploaded == total {
			printProgress(uploaded, total, start)
			nextPrint = time.Now().Add(time.Second)
		}
	}

	last := len(chunks) - 1
	if workers == 1 || last == 0 {
		for index := 0; index <= last; index++ {
			res := uploadOneChunk(ctx, r, uploadURL, ukey, chunks, index, poster)
			if res.err != nil {
				return "", nil, fmt.Errorf("upload chunk at offset %d: %w", chunks[res.index].position, res.err)
			}
			macs[res.index] = res.mac
			if index == last && len(res.body) > 0 {
				completion = string(res.body)
			}
			reportProgress(res.size)
		}
		return completion, macs, nil
	}

	workerCount := minInt(workers, last)
	jobs := make(chan int)
	results := make(chan uploadChunkResult, workerCount)
	var wg sync.WaitGroup
	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
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
					res := uploadOneChunk(ctx, r, uploadURL, ukey, chunks, index, poster)
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
		macs[res.index] = res.mac
		reportProgress(res.size)
	}
	if firstErr != nil {
		return "", nil, firstErr
	}

	res := uploadOneChunk(ctx, r, uploadURL, ukey, chunks, last, poster)
	if res.err != nil {
		return "", nil, fmt.Errorf("upload chunk at offset %d: %w", chunks[res.index].position, res.err)
	}
	macs[res.index] = res.mac
	if len(res.body) > 0 {
		completion = string(res.body)
	}
	reportProgress(res.size)
	return completion, macs, nil
}

func uploadOneChunk(ctx context.Context, r io.ReaderAt, uploadURL string, ukey []uint32, chunks []chunkSize, index int, poster uploadChunkPoster) uploadChunkResult {
	ch := chunks[index]
	res := uploadChunkResult{index: index, size: ch.size}
	buf := make([]byte, ch.size)
	if ch.size > 0 {
		if _, err := r.ReadAt(buf, ch.position); err != nil {
			res.err = err
			return res
		}
	}
	encData, mac, err := encryptUploadChunk(buf, ukey, ch.position)
	if err != nil {
		res.err = err
		return res
	}
	body, err := poster(ctx, uploadURL, ch.position, encData)
	if err != nil {
		res.err = err
		return res
	}
	res.body = body
	res.mac = mac
	return res
}

type transferOptions struct {
	Title    string
	Message  string
	From     string
	Password string
	Expire   int
}

func setTransferOptions(api *apiClient, xh string, opt transferOptions) error {
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
	if err := api.call([]map[string]any{req}, nil, &res); err != nil {
		return err
	}
	if len(res) != 1 || string(res[0]) != "0" {
		return fmt.Errorf("xm failed: %s", rawList(res))
	}
	return nil
}

func setTransferRecipient(api *apiClient, xh, email string, schedule int64) error {
	req := map[string]any{"a": "xr", "xh": xh, "e": email}
	if schedule > 0 {
		req["s"] = schedule
	}
	var res []json.RawMessage
	if err := api.call([]map[string]any{req}, nil, &res); err != nil {
		return err
	}
	if len(res) != 1 || (len(res[0]) > 0 && res[0][0] == '-') {
		return fmt.Errorf("xr failed for %s: %s", email, rawList(res))
	}
	return nil
}

func closeTransfer(api *apiClient, xh string) error {
	var res []json.RawMessage
	if err := api.call([]map[string]any{{"a": "xc", "xh": xh}}, nil, &res); err != nil {
		return err
	}
	if len(res) != 1 || string(res[0]) != "0" {
		return fmt.Errorf("xc failed: %s", rawList(res))
	}
	return nil
}

func (c *apiClient) call(payload any, query url.Values, out any) error {
	c.seq++
	u := fmt.Sprintf("%s/cs?id=%d", c.base, time.Now().UnixMilli()+int64(c.seq))
	if c.sid != "" {
		if query == nil {
			query = url.Values{}
		}
		query.Set("sid", c.sid)
	}
	if len(query) > 0 {
		u += "&" + query.Encode()
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	hashcash := ""
	for attempt := 0; attempt < 6; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), apiRequestTimeout)
		req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
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
			return sanitizeHTTPError(err, req.URL)
		}
		resBody, readErr := readBoundedResponse(resp.Body, maxAPIResponseSize)
		resp.Body.Close()
		cancel()
		if readErr != nil {
			return readErr
		}

		if resp.StatusCode == http.StatusPaymentRequired {
			challenge := resp.Header.Get("X-Hashcash")
			if challenge != "" {
				hashcash, err = generateHashcashToken(challenge)
				if err != nil {
					return err
				}
				continue
			}
		}

		if isTransientHTTPStatus(resp.StatusCode) && attempt < 5 {
			time.Sleep(apiRetryDelay(attempt))
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("API HTTP %s: %s", resp.Status, strings.TrimSpace(string(resBody)))
		}
		if challenge, ok := hashcashChallengeFromBody(resBody); ok {
			var err error
			hashcash, err = generateHashcashToken(challenge)
			if err != nil {
				return err
			}
			continue
		}
		if code, ok := negativeAPICode(resBody); ok {
			if isTransientAPICode(code) && attempt < 5 {
				time.Sleep(apiRetryDelay(attempt))
				continue
			}
			return apiError{Code: code, Body: strings.TrimSpace(string(resBody))}
		}
		if code, ok := firstNegativeArrayCode(resBody); ok {
			if isTransientAPICode(code) && attempt < 5 {
				time.Sleep(apiRetryDelay(attempt))
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
			select {
			case <-time.After(apiRetryDelay(attempt - 1)):
			case <-parent.Done():
				return nil, parent.Err()
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

func encryptUploadChunk(chunk []byte, ukey []uint32, offset int64) ([]byte, []byte, error) {
	key := wordsToBytes(ukey[:4])
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	ctrWords := []uint32{ukey[4], ukey[5], uint32(uint64(offset) / 0x1000000000), uint32(offset / 16)}
	encrypted := append([]byte(nil), chunk...)
	cipher.NewCTR(block, wordsToBytes(ctrWords)).XORKeyStream(encrypted, encrypted)

	// padNull always returns a freshly allocated buffer that never aliases chunk, so
	// the CBC-MAC can run in place over it. Do not "optimize" padNull to return its
	// input when already block-aligned: that would encrypt the caller's plaintext.
	padded := padNull(chunk, aes.BlockSize)
	mac := make([]byte, aes.BlockSize)
	if len(padded) > 0 {
		iv := wordsToBytes([]uint32{ukey[4], ukey[5], ukey[4], ukey[5]})
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(padded, padded)
		copy(mac, padded[len(padded)-aes.BlockSize:])
	}
	return encrypted, mac, nil
}

func buildFileKey(ukey []uint32, macs [][]byte) ([]uint32, error) {
	key := wordsToBytes(ukey[:4])
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	macData := make([]byte, aes.BlockSize)
	enc := cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize))
	for _, mac := range macs {
		enc.CryptBlocks(macData, mac)
	}
	t := bytesToWords(macData)
	metaMac := []uint32{t[0] ^ t[1], t[2] ^ t[3]}
	return []uint32{
		ukey[0] ^ ukey[4],
		ukey[1] ^ ukey[5],
		ukey[2] ^ metaMac[0],
		ukey[3] ^ metaMac[1],
		ukey[4],
		ukey[5],
		metaMac[0],
		metaMac[1],
	}, nil
}

func generateHashcashToken(challenge string) (string, error) {
	parts := strings.Split(challenge, ":")
	if len(parts) < 4 {
		return "", fmt.Errorf("invalid hashcash challenge %q", challenge)
	}
	version, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", err
	}
	if version != 1 {
		return "", fmt.Errorf("unsupported hashcash challenge version %d", version)
	}
	easiness, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", err
	}
	if easiness < 0 || easiness > 255 {
		return "", fmt.Errorf("invalid hashcash easiness %d", easiness)
	}
	tokenText := parts[3]
	token, err := decodeFlexibleBase64(tokenText)
	if err != nil {
		return "", err
	}
	if len(token) < hashcashChunkSize {
		return "", fmt.Errorf("hashcash token is too short: %d bytes", len(token))
	}

	baseVal := uint64(((easiness & 63) << 1) + 1)
	shifts := uint((easiness>>6)*7 + 3)
	threshold := uint64(^uint32(0))
	if shifts < 64 {
		threshold = baseVal << shifts
	}
	if threshold > uint64(^uint32(0)) {
		threshold = uint64(^uint32(0))
	}

	prefix, ok := searchHashcashPrefix(token[:hashcashChunkSize], threshold)
	if !ok {
		return "", fmt.Errorf("hashcash challenge too hard (easiness %d): no solution within %d attempts", easiness, hashcashMaxAttempts)
	}
	return fmt.Sprintf("1:%s:%s", tokenText, b64Encode(prefix)), nil
}

// searchHashcashPrefix looks for a 4-byte prefix whose SHA-256 over the repeated
// token falls under threshold. Each hash covers a 12 MiB buffer, so the search is
// striped across cores; workers take disjoint prefixes and share one attempt budget
// so a hostile or misconfigured easiness cannot wedge the CLI indefinitely.
func searchHashcashPrefix(token []byte, threshold uint64) ([]byte, bool) {
	workers := min(runtime.NumCPU(), 4)
	if workers < 1 {
		workers = 1
	}

	var (
		remaining = int64(hashcashMaxAttempts)
		found     atomic.Bool
		mu        sync.Mutex
		solution  []byte
		wg        sync.WaitGroup
	)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(start uint32) {
			defer wg.Done()
			buffer := make([]byte, hashcashPrefixSize+hashcashIterations*hashcashChunkSize)
			for i := 0; i < hashcashIterations; i++ {
				copy(buffer[hashcashPrefixSize+i*hashcashChunkSize:], token)
			}
			for counter := start; !found.Load(); counter += uint32(workers) {
				if atomic.AddInt64(&remaining, -1) < 0 {
					return
				}
				// The reference implementation increments the prefix bytes low-first,
				// which is a little-endian uint32 counter starting at zero.
				binary.LittleEndian.PutUint32(buffer[:hashcashPrefixSize], counter)
				sum := sha256.Sum256(buffer)
				if uint64(binary.BigEndian.Uint32(sum[:4])) <= threshold {
					mu.Lock()
					if solution == nil {
						solution = append([]byte(nil), buffer[:hashcashPrefixSize]...)
					}
					mu.Unlock()
					found.Store(true)
					return
				}
			}
		}(uint32(w))
	}
	wg.Wait()
	return solution, solution != nil
}

func hashcashChallengeFromBody(body []byte) (string, bool) {
	var raw []json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || len(raw) < 2 || strings.TrimSpace(string(raw[0])) != "-27" {
		return "", false
	}
	var challenge string
	if err := json.Unmarshal(raw[1], &challenge); err != nil {
		return "", false
	}
	return challenge, challenge != ""
}

func getChunkSizes(size int64) []chunkSize {
	var chunks []chunkSize
	var p int64
	for i := 1; size > 0; i++ {
		chunk := i * 131072
		if i > 8 {
			chunk = 1048576
		}
		if size < int64(chunk) {
			chunk = int(size)
		}
		chunks = append(chunks, chunkSize{position: p, size: chunk})
		p += int64(chunk)
		size -= int64(chunk)
	}
	return chunks
}

func encryptAttr(attrs map[string]any, key []uint32) (string, error) {
	data, err := json.Marshal(attrs)
	if err != nil {
		return "", err
	}
	buf := append([]byte("MEGA"), data...)
	buf = padNull(buf, aes.BlockSize)
	aesKey, err := attrAESKey(key)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(wordsToBytes(aesKey))
	if err != nil {
		return "", err
	}
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(buf, buf)
	return b64Encode(buf), nil
}

func decryptNodeName(attr64, key64 string) (string, error) {
	attr, err := b64Decode(attr64)
	if err != nil {
		return "", err
	}
	keyBytes, err := b64Decode(key64)
	if err != nil {
		return "", err
	}
	if len(attr)%aes.BlockSize != 0 {
		return "", errors.New("attribute block is not AES-aligned")
	}
	keyWords := bytesToWords(keyBytes)
	aesKey, err := attrAESKey(keyWords)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(wordsToBytes(aesKey))
	if err != nil {
		return "", err
	}
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(attr, attr)
	attr = bytes.TrimRight(attr, "\x00")
	if !bytes.HasPrefix(attr, []byte("MEGA")) {
		return "", errors.New("bad attribute canary")
	}
	var obj map[string]any
	if err := json.Unmarshal(attr[4:], &obj); err != nil {
		return "", err
	}
	if n, ok := obj["n"].(string); ok {
		return n, nil
	}
	return "", nil
}

func attrAESKey(key []uint32) ([]uint32, error) {
	switch len(key) {
	case 4:
		return append([]uint32(nil), key...), nil
	case 8:
		return []uint32{key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7]}, nil
	default:
		return nil, fmt.Errorf("attribute key must contain 4 or 8 words, got %d", len(key))
	}
}

func deriveTransferPassword(xh, password string) (string, error) {
	raw, err := b64Decode(xh)
	if err != nil {
		return "", err
	}
	if len(raw) < 6 {
		return "", errors.New("transfer handle is too short for password salt")
	}
	saltPart := raw[len(raw)-6:]
	salt := append(append(append([]byte{}, saltPart...), saltPart...), saltPart...)
	key, err := pbkdf2.Key(sha256.New, strings.TrimSpace(password), salt, 100000, 32)
	if err != nil {
		return "", err
	}
	return b64Encode(key), nil
}

func randomWords(n int) ([]uint32, error) {
	buf := make([]byte, n*4)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return bytesToWords(buf), nil
}

func wordsToBytes(words []uint32) []byte {
	buf := make([]byte, len(words)*4)
	for i, w := range words {
		binary.BigEndian.PutUint32(buf[i*4:], w)
	}
	return buf
}

func bytesToWords(buf []byte) []uint32 {
	words := make([]uint32, len(buf)/4)
	for i := range words {
		words[i] = binary.BigEndian.Uint32(buf[i*4:])
	}
	return words
}

func encryptWords(key, words []uint32) ([]uint32, error) {
	if len(words)%4 != 0 {
		return nil, fmt.Errorf("plaintext must contain complete AES blocks, got %d words", len(words))
	}
	block, err := aes.NewCipher(wordsToBytes(key))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(words)*4)
	src := wordsToBytes(words)
	for i := 0; i < len(src); i += aes.BlockSize {
		block.Encrypt(out[i:], src[i:i+aes.BlockSize])
	}
	return bytesToWords(out), nil
}

func decryptWords(key, words []uint32) ([]uint32, error) {
	if len(words)%4 != 0 {
		return nil, fmt.Errorf("ciphertext must contain complete AES blocks, got %d words", len(words))
	}
	block, err := aes.NewCipher(wordsToBytes(key))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(words)*4)
	src := wordsToBytes(words)
	for i := 0; i < len(src); i += aes.BlockSize {
		block.Decrypt(out[i:], src[i:i+aes.BlockSize])
	}
	return bytesToWords(out), nil
}

func padNull(buf []byte, blockSize int) []byte {
	pad := blockSize - len(buf)%blockSize
	if pad == blockSize {
		return append([]byte(nil), buf...)
	}
	out := make([]byte, len(buf)+pad)
	copy(out, buf)
	return out
}

func b64Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func decodeFlexibleBase64(s string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		data, err := enc.DecodeString(s)
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func rawList(raw []json.RawMessage) string {
	b, _ := json.Marshal(raw)
	return string(b)
}

func configPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			if err != nil {
				return "", err
			}
			return "", homeErr
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "transferit-cli", "config.json"), nil
}

func mustConfigPath() string {
	path, err := configPath()
	if err != nil {
		return filepath.Join(".config", "transferit-cli", "config.json")
	}
	return path
}

func loadSavedConfig() (savedConfig, bool, error) {
	path, err := configPath()
	if err != nil {
		return savedConfig{}, false, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return savedConfig{Version: 1}, false, nil
	}
	if err != nil {
		return savedConfig{}, false, err
	}
	var cfg savedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return savedConfig{}, false, err
	}
	if cfg.Version == 0 {
		cfg.Version = 1
	}
	return cfg, true, nil
}

func saveSavedConfig(cfg savedConfig) error {
	if cfg.Version == 0 {
		cfg.Version = 1
	}
	path, err := configPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("config directory is not a regular directory: %s", dir)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

func saveAccountSession(email, passwordToStore string, sess session) error {
	cfg, _, err := loadSavedConfig()
	if err != nil {
		return err
	}
	cfg.Account = savedAccount{
		Email:     normalizeEmail(email),
		Password:  passwordToStore,
		SID:       sess.sid,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return saveSavedConfig(cfg)
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// passwordToPersist decides whether the account password stays on disk. A password
// the user already opted into saving is kept — and refreshed — for the same account,
// so an ordinary re-login does not silently strip the credential that later
// unattended runs depend on once the saved session expires. Switching accounts drops
// the previous account's password, which is what logging in as someone else means.
func passwordToPersist(cfg savedConfig, email, password string, savePassword, passwordFromConfig bool) string {
	if savePassword || passwordFromConfig {
		return password
	}
	if cfg.Account.Password != "" && strings.EqualFold(normalizeEmail(email), normalizeEmail(cfg.Account.Email)) {
		return password
	}
	return ""
}

func promptLine(label string) (string, error) {
	fmt.Print(label)
	line, err := stdinReader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func promptSecret(label string) (string, error) {
	fmt.Print(label)
	echoDisabled := false
	if st, err := os.Stdin.Stat(); err == nil && (st.Mode()&os.ModeCharDevice) != 0 {
		cmd := exec.Command("stty", "-echo")
		cmd.Stdin = os.Stdin
		if cmd.Run() == nil {
			echoDisabled = true
			defer func() {
				restore := exec.Command("stty", "echo")
				restore.Stdin = os.Stdin
				_ = restore.Run()
				fmt.Println()
			}()
		}
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if !echoDisabled {
		fmt.Println()
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func isNegativeJSON(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return strings.HasPrefix(s, "-")
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
	switch code {
	case -3, -4:
		return true
	default:
		return false
	}
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

func stringToWords(s string) []uint32 {
	data := []byte(s)
	if rem := len(data) % 4; rem != 0 {
		data = append(data, make([]byte, 4-rem)...)
	}
	return bytesToWords(data)
}

func readMPI(buf []byte, pos int) (*big.Int, int, error) {
	if pos+2 > len(buf) {
		return nil, pos, errors.New("missing MPI length")
	}
	bits := int(binary.BigEndian.Uint16(buf[pos : pos+2]))
	pos += 2
	byteLen := (bits + 7) / 8
	if byteLen < 0 || pos+byteLen > len(buf) {
		return nil, pos, errors.New("MPI length exceeds buffer")
	}
	return new(big.Int).SetBytes(buf[pos : pos+byteLen]), pos + byteLen, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func wordsEqual(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func splitEmails(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseSchedule(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return v, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, fmt.Errorf("--send-at must be Unix seconds or RFC3339: %w", err)
	}
	return t.Unix(), nil
}

func decodeMaybeBase64(s string) string {
	if s == "" {
		return ""
	}
	if b, err := b64Decode(s); err == nil {
		return string(b)
	}
	return s
}

// safeNameReplacer is built once: the shrinking "\x00" -> "" rule forces strings onto
// its generic trie replacer, which is expensive to construct and gets rebuilt for
// every path component of every node otherwise. Replacers are safe to share.
var safeNameReplacer = strings.NewReplacer(
	"/", "_", "\\", "_", "\x00", "",
	"<", "_", ">", "_", ":", "_", "\"", "_",
	"|", "_", "?", "_", "*", "_",
)

func safeName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unnamed"
	}
	s = safeNameReplacer.Replace(s)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
	if s == "." || s == ".." {
		s = "_" + s
	}
	s = strings.TrimRight(s, " .")
	if s == "" {
		return "unnamed"
	}
	base := strings.TrimRight(strings.ToUpper(strings.SplitN(s, ".", 2)[0]), " ")
	if isWindowsReservedName(base) || looksLikeWindowsShortName(base) {
		return "_" + s
	}
	return s
}

func isWindowsReservedName(base string) bool {
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CONIN$" || base == "CONOUT$" {
		return true
	}
	runes := []rune(base)
	if len(runes) != 4 || (string(runes[:3]) != "COM" && string(runes[:3]) != "LPT") {
		return false
	}
	return (runes[3] >= '1' && runes[3] <= '9') || runes[3] == '¹' || runes[3] == '²' || runes[3] == '³'
}

func looksLikeWindowsShortName(base string) bool {
	tilde := strings.LastIndexByte(base, '~')
	if tilde < 1 || tilde == len(base)-1 {
		return false
	}
	prefixLength := len([]rune(base[:tilde]))
	if prefixLength < 1 || prefixLength > 6 {
		return false
	}
	for _, r := range base[tilde+1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func copyWithProgress(dst io.Writer, src io.Reader, done, total int64) error {
	buf := make([]byte, 1024*1024)
	start := time.Now()
	nextPrint := time.Now()
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			written, err := dst.Write(buf[:n])
			if err != nil {
				return err
			}
			if written != n {
				return io.ErrShortWrite
			}
			done += int64(n)
			if time.Now().After(nextPrint) || done == total {
				printProgress(done, total, start)
				nextPrint = time.Now().Add(time.Second)
			}
		}
		if rerr == io.EOF {
			fmt.Println()
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

func printProgress(done, total int64, start time.Time) {
	elapsed := time.Since(start).Seconds()
	speed := float64(done) / math.Max(elapsed, 0.001)
	if total > 0 {
		fmt.Printf("\r  %.1f%%  %s / %s  %s/s", float64(done)*100/float64(total), humanBytes(done), humanBytes(total), humanBytes(int64(speed)))
	} else {
		fmt.Printf("\r  %s  %s/s", humanBytes(done), humanBytes(int64(speed)))
	}
}

func humanBytes(n int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}
