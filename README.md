# transferit-cli

A standalone Go command-line tool for downloading from and uploading to
`transfer.it`.

The repository contains:

- `script.go`: the complete Go source code.
- `script_test.go`: regression tests for parsing, crypto helpers, chunk sizing,
  and API error parsing.
- `go.mod`: module metadata. The tool uses only the Go standard library.
- `README.md`: user guide.
- `API.md`: developer notes for the reverse-engineered transfer.it/MEGA API.

The compiled `transferit` binary is generated locally and ignored by git.

## Quick Start

From this directory:

```bash
cd transferit-cli
```

Download a public transfer:

```bash
./transferit https://transfer.it/t/TRANSFER_HANDLE --out /tmp/downloads
```

Download a password-protected transfer:

```bash
./transferit https://transfer.it/t/PASSWORD_PROTECTED_HANDLE --password YOUR_PASSWORD --out /tmp/downloads
```

Upload one file:

```bash
./transferit upload --title "My transfer" --message "Here is the file" --expire 7 ./file.bin
```

Upload a directory:

```bash
./transferit upload --title "Project archive" --expire 30 ./my-folder
```

Log in to a MEGA account and save it for later uploads:

```bash
./transferit account login --email user@example.com --save-password
```

Upload using the saved account session instead of a guest session:

```bash
./transferit upload --account --title "Account-backed transfer" ./file.bin
```

Upload and add recipients using the transfer.it "Send files" behavior:

```bash
./transferit upload \
  --to alice@example.com,bob@example.com \
  --from sender@example.com \
  --title "Scheduled delivery" \
  --message "Files are attached" \
  --send-at 2030-01-01T00:00:00Z \
  --expire 30 \
  ./file.bin
```

## Building

Build the CLI:

```bash
go build -o transferit script.go
```

To run from source without building:

```bash
go run script.go --help
```

The code is written for Go 1.22 and uses only the standard library.

## Commands

The tool has two modes:

- `download`: download a transfer.it link.
- `upload`: upload files or directories and create a transfer.it link.
- `account`: log in, inspect, or remove a saved MEGA account session.

For convenience, a transfer URL as the first argument is treated as a download:

```bash
./transferit https://transfer.it/t/TRANSFER_HANDLE
```

This is equivalent to:

```bash
./transferit download https://transfer.it/t/TRANSFER_HANDLE
```

## Download Usage

```bash
./transferit download <transfer.it-url> [--password PASS] [--out DIR]
./transferit <transfer.it-url> [--password PASS] [--out DIR]
```

Download options:

| Flag | Meaning | Default |
| --- | --- | --- |
| `--password PASS` | Password for password-protected transfer links. | Prompt if required and not provided |
| `--out DIR` | Output directory. | Current directory |

Examples:

```bash
./transferit https://transfer.it/t/PASSWORD_PROTECTED_HANDLE --password YOUR_PASSWORD --out /tmp/out
```

```bash
./transferit download https://transfer.it/t/TRANSFER_HANDLE --out /tmp/out
```

### Download Behavior

- The tool fetches transfer metadata from the transfer.it/MEGA API.
- It derives the transfer password token when `--password` is supplied.
- It decrypts node attributes locally to recover real file and folder names.
- It downloads file content through the transfer.it direct download endpoint.
- Existing complete files are skipped.
- Existing partial files are resumed with an HTTP `Range` request.
- Multi-file or directory transfers are placed inside a subdirectory named after
  the transfer title.
- Empty folders are recreated when downloading directory transfers.

## Upload Usage

```bash
./transferit upload [options] FILE [FILE...]
./transferit upload [options] DIR [DIR...]
./transferit upload [options] FILE DIR FILE ...
```

Upload options:

| Flag | Meaning | Default |
| --- | --- | --- |
| `--title TEXT` | Transfer title. | Single input basename, or timestamp for multiple inputs |
| `--message TEXT` | Transfer message. | Empty |
| `--from EMAIL` | "Your email (optional)" sender field. | Empty |
| `--password PASS` | Add password protection to the transfer link. | No password |
| `--expire DAYS` | Availability/expiry in days. Supported values: `0`, `7`, `30`, `90`. | `90` |
| `--to EMAILS` | Comma-separated recipient emails for "Send files". | Empty |
| `--send-at TIME` | Scheduled send date/time. Unix seconds or RFC3339. | Send immediately |
| `--account` | Use a saved/logged-in MEGA account session instead of a guest session. | Disabled |
| `--account-email EMAIL` | MEGA account email for one-shot login during upload. | Saved account email |
| `--account-password PASS` | MEGA account password for one-shot login during upload. | Saved password or prompt |
| `--account-mfa CODE` | MEGA two-factor authentication code, if required. | Empty |
| `--save-account-password` | Save the account password when logging in during upload. | Disabled |
| `--upload-workers N` | Parallel upload chunk workers per file. Use `1` for strictly sequential uploads. | `4` |

Examples:

```bash
./transferit upload --title "Reports" --expire 90 ./report.pdf
```

```bash
./transferit upload \
  --title "Password protected" \
  --message "Use the password I sent you" \
  --password "Secret123" \
  --expire 7 \
  ./archive.zip
```

```bash
./transferit upload \
  --title "Directory upload" \
  --message "Nested folders are preserved" \
  --expire 30 \
  ./project-folder
```

```bash
./transferit upload \
  --to recipient@example.com \
  --from sender@example.com \
  --title "Send files example" \
  --message "Scheduled message" \
  --send-at 2030-01-01T00:00:00Z \
  --expire 30 \
  ./file.bin
```

### Upload Behavior

- By default, the tool creates an anonymous MEGA session, matching the behavior
  transfer.it uses for guest uploads.
- With `--account`, the tool uses a saved or freshly logged-in MEGA account
  session instead.
- It creates a new transfer root with the transfer.it transfer API.
- For directory inputs, it recursively walks the directory tree.
- Every local directory is created as a remote folder node, including empty
  directories.
- Every regular file is encrypted locally and uploaded into its matching remote
  folder. Upload chunks are posted in parallel by default; the final chunk is
  still sent last so the upload server can return the completion handle.
- Special files such as devices, sockets, and symlinks are rejected.
- After all files are uploaded, transfer metadata is applied:
  - title
  - message
  - sender email
  - password
  - expiry
  - recipients
  - scheduled send time
- The transfer is then closed/finalized.

## Account Login

Account support is opt-in. Anonymous uploads remain the default.

Log in and save a reusable session:

```bash
./transferit account login --email user@example.com
```

Save the password too, so future `--account` uploads can refresh the session
without asking again:

```bash
./transferit account login --email user@example.com --save-password
```

Use two-factor authentication when required:

```bash
./transferit account login --email user@example.com --mfa 123456
```

Check what is saved:

```bash
./transferit account status
```

Remove the saved account config:

```bash
./transferit account logout
```

When `--account` is used, the CLI prefers the saved `sid` session first. If you
pass `--account-password`, or if no saved session exists and a saved password is
available, it logs in again and refreshes the saved session. If a saved session
is rejected by the API and a password is available, the CLI automatically logs
in again, updates the saved `sid`, and retries transfer creation.

The config file is stored at:

```text
~/.config/transferit-cli/config.json
```

The file is written with mode `0600`. If `--save-password` or
`--save-account-password` is used, the MEGA password is stored in that file in
plaintext. This is convenient for automation, but it means anyone who can read
that config file can use the account.

MEGA may return a login proof-of-work challenge through the `X-Hashcash`
header. The CLI solves that challenge automatically before retrying the login.
The API client also retries transient MEGA/transfer.it failures such as API
`-3`, API `-4`, HTTP `429`, and common `5xx` gateway/server responses.

## Directory Handling

Uploading a directory preserves the top-level directory name.

For example:

```text
my-folder/
  root.txt
  empty/
  sub/
    nested.txt
```

Uploaded with:

```bash
./transferit upload ./my-folder
```

Downloads back as:

```text
<transfer-title>/my-folder/
  root.txt
  empty/
  sub/
    nested.txt
```

If multiple files or folders are uploaded, they are all placed under the transfer
root and keep their relative top-level names.

## Scheduled Sending

`--send-at` is only meaningful when `--to` is provided.

Accepted formats:

```bash
--send-at 1893456000
--send-at 2030-01-01T00:00:00Z
```

The timestamp sent to transfer.it is Unix seconds.

## Passwords

For download, `--password` is the human password for the transfer link:

```bash
./transferit https://transfer.it/t/PASSWORD_PROTECTED_HANDLE --password YOUR_PASSWORD
```

For upload, `--password` sets the password required by future downloaders:

```bash
./transferit upload --password Lol123 ./file.bin
```

The tool derives the transfer.it password token using PBKDF2-HMAC-SHA256 with
100,000 iterations and the transfer handle-derived salt, matching the webclient
behavior.

## Progress and Resume

Downloads:

- Show percentage, transferred bytes, total bytes, and current average speed.
- Resume partial files if the destination file already exists and is smaller
  than the remote size.
- Skip files that already match the remote byte size.

Uploads:

- Show percentage, transferred bytes, total bytes, and current average speed for
  each file.
- Do not resume interrupted uploads yet. Re-run the upload command to create a
  fresh transfer.

## Verification Examples

Create a generated 500 MiB file:

```bash
truncate -s 500M /tmp/transferit-500m.bin
```

Upload it:

```bash
./transferit upload --title "500 MiB test" --expire 7 /tmp/transferit-500m.bin
```

Download it back:

```bash
mkdir -p /tmp/transferit-500m-download
./transferit https://transfer.it/t/YOUR_TRANSFER_HANDLE --out /tmp/transferit-500m-download
```

Compare hashes:

```bash
sha256sum /tmp/transferit-500m.bin /tmp/transferit-500m-download/transferit-500m.bin
```

## How It Works

The tool uses transfer.it's MEGA-backed API endpoints directly.

Download flow:

1. Parse the transfer handle from `/t/<handle>`.
2. Call `xi` to read transfer metadata.
3. If the transfer is password-protected, derive the password token and validate
   it with `xv`.
4. Call `f` with the transfer handle to get the node tree.
5. Decrypt each node's attributes locally to recover names.
6. Download files from `bt7.api.mega.co.nz/cs/g?...`.
7. Use `Referer: https://transfer.it/t/<handle>` and
   `Origin: https://transfer.it`, which the transfer endpoint expects.

Upload flow:

1. Create an anonymous MEGA session with the public MEGA API.
2. Create a transfer root using transfer.it's `xn` command.
3. Create directory nodes using transfer.it's `xp` command.
4. Request an upload URL with command `u`.
5. Encrypt upload chunks locally with AES-CTR and compute MEGA-compatible MACs.
6. POST encrypted chunks to the upload server.
7. Finalize each uploaded file with command `xp`.
8. Apply transfer metadata with command `xm`.
9. Add recipients/schedule with command `xr`, when requested.
10. Close the transfer with command `xc`.

## Limitations

- Upload resume is not implemented.
- Symlinks and special files are not followed or uploaded.
- Directory downloads recreate empty folders, but downloads still skip files
  based only on byte size, not hash.
- Prebuilt binaries are not committed by default. Build locally with
  `go build -o transferit script.go`, or publish binaries separately through
  GitHub Releases.
- transfer.it is not a public stable API. If their webclient protocol changes,
  this tool may need updates.

## Troubleshooting

`invalid transfer password`

: The password was rejected by transfer.it. Check spelling and shell quoting.

`download HTTP 403` or redirect to HTML

: The transfer may have expired, been removed, or transfer.it may have changed
  its direct download behavior.

`API error -14`

: Usually means the transfer requires a password or the derived password token
  is wrong.

`special file is not supported`

: The upload input contains a symlink, device, socket, or another non-regular
  filesystem entry. Upload regular files and directories only.

`upload server did not return a completion handle`

: The upload server did not finalize the file upload. Re-run the command; upload
  resume is not currently implemented.

## Security Notes

- The tool does not execute downloaded files.
- Files are written exactly as served by transfer.it.
- Upload file encryption is performed locally before content is sent to the
  upload server.
- Passwords passed on the command line can be visible in shell history and
  process listings. For downloads, omit `--password` to be prompted instead.
