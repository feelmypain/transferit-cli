package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
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

// hashcashMaxAttempts bounds the proof-of-work search. Each attempt hashes 12 MiB,
// and a legitimate challenge resolves in well under a thousand attempts, so this
// leaves ample headroom while capping worst-case runtime on a hostile difficulty.
var hashcashMaxAttempts = 1 << 14

var (
	// transferAPI is a var so tests can point downloads at httptest servers.
	transferAPI = "https://bt7.api.mega.co.nz"

	httpClient = newHTTPClient()
	linkRE     = regexp.MustCompile("(?i)(?:^|[\\s<(\"'`])(?:https?://)?(?:www\\.)?transfer\\.it/t/([A-Za-z0-9_-]+)")

	// defaultStdinReader and stdinReader are shared across prompts: bufio reads
	// ahead, so a per-prompt reader would swallow later lines of a piped script.
	// Checking stdinReader == defaultStdinReader also tells promptSecret whether
	// input is still attached to os.Stdin rather than a test-injected reader.
	defaultStdinReader = bufio.NewReader(os.Stdin)
	stdinReader        = defaultStdinReader

	// errDownloadTransient marks failures worth retrying with bytes already on disk;
	// errRangeRejected marks a resume the server refused, requiring a restart from
	// byte zero; errIntegrityMismatch marks a completed download whose MAC failed.
	errDownloadTransient = errors.New("transient download failure")
	errRangeRejected     = errors.New("server rejected the resume range")
	errIntegrityMismatch = errors.New("MAC mismatch")
)

type session struct {
	sid       string
	masterKey []uint32
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := os.Args[1]
	var err error
	switch {
	case cmd == "download":
		err = runDownload(ctx, os.Args[2:])
	case cmd == "upload":
		err = runUpload(ctx, os.Args[2:])
	case cmd == "account":
		err = runAccount(ctx, os.Args[2:])
	// Accept a bare "transfer.it/t/HANDLE" too: parseTransferHandle already does, so
	// rejecting it here as an unknown command was an inconsistency.
	case strings.HasPrefix(cmd, "http://") || strings.HasPrefix(cmd, "https://") || linkRE.MatchString(cmd):
		err = runDownload(ctx, os.Args[1:])
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

func programName() string {
	if len(os.Args) > 0 && os.Args[0] != "" {
		base := filepath.Base(os.Args[0])
		if base != "" && base != "." && base != string(filepath.Separator) {
			return base
		}
	}
	return "transferit"
}

func usage() {
	prog := programName()
	fmt.Fprintf(os.Stderr, `Usage:
  %[1]s <transfer.it-url> [--password PASS] [--out DIR]
  %[1]s download <transfer.it-url> [--password PASS] [--out DIR]

  %[1]s upload [options] FILE_OR_DIR [FILE_OR_DIR...]
  %[1]s account login --email EMAIL [--password PASS] [--save-password]
  %[1]s account status
  %[1]s account logout

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
  %[1]s https://transfer.it/t/TRANSFER_HANDLE --password YOUR_LINK_PASSWORD
  %[1]s account login --email user@example.com --save-password
  %[1]s upload --title "Big test" --message "hello" --expire 7 ./file.bin
  %[1]s upload --account --title "Account upload" ./file.bin
  %[1]s upload --to a@example.com,b@example.com --from me@example.com --send-at 2026-06-01T10:30:00Z ./file.bin
`, prog)
}
