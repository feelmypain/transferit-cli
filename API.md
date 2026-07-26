# transfer.it API Notes

This document describes the transfer.it protocol as implemented by this
repository. It is not an official transfer.it document. The behavior was
reverse-engineered from the web client and confirmed by the Go implementation
in `script.go`.

transfer.it uses MEGA-style APIs and MEGA-style client-side crypto primitives.
Most JSON API calls go through the `/cs` command endpoint, while file bytes use
separate upload and download URLs.

The Go implementation does not scrape HTML. It talks directly to the API,
constructs the same JSON commands as the site, and performs the same key,
attribute, upload-chunk, and password-token calculations locally.

## Important Concepts

### Base URLs

The code uses two API hosts:

```text
https://g.api.mega.co.nz
https://bt7.api.mega.co.nz
```

`g.api.mega.co.nz` is used to create an anonymous MEGA session for upload.
`bt7.api.mega.co.nz` is used for transfer.it transfer metadata, public node
listing, file download, transfer creation, folder creation, and upload
management.

In `script.go`, these are the constants:

```go
const (
	megaAPI     = "https://g.api.mega.co.nz"
	transferAPI = "https://bt7.api.mega.co.nz"
	origin      = "https://transfer.it"
)
```

### Command Endpoint Format

Most API calls are sent to:

```text
POST /cs?id=<request-id>
Content-Type: application/json
User-Agent: Mozilla/5.0

[
  { "a": "<command>", "...": "..." }
]
```

The request body is always a JSON array, even when only one command is sent.
The response is normally a JSON array whose positions match the requested
commands.

For authenticated upload/management calls, append the anonymous session id:

```text
POST /cs?id=<request-id>&sid=<sid>
```

For public transfer node listing, append the transfer handle:

```text
POST /cs?id=<request-id>&x=<transfer-handle>
```

For password-protected public transfers, also append the derived password token:

```text
POST /cs?id=<request-id>&x=<transfer-handle>&pw=<password-token>
```

The `id` value only needs to be unique-ish per request. The Go code uses the
current Unix millisecond timestamp plus a local sequence counter.

See `apiClient.call` in `script.go`.

### Error Handling

MEGA-style APIs often return negative integers for errors. Sometimes the whole
HTTP response body is a negative number, for example:

```json
-14
```

Sometimes a command result inside the response array is negative:

```json
[-14]
```

The implementation treats a bare negative body, or a negative first command
result inside a response array, as failure unless the endpoint is known to
return `0` for success.

Observed or useful error meanings:

| Code | Meaning in this context |
| --- | --- |
| `-14` | Bad key, commonly an invalid transfer password token |
| `-15` | Invalid or missing session id |
| `-9` | Missing, expired, or unavailable resource |
| `-3` | Temporary failure; retryable |
| `-4` | Rate limit or temporary overload; retryable |

The API may return other negative codes. The safest implementation strategy is
to surface the raw code and the command that caused it.

The CLI retries retryable API codes `-3` and `-4` whether they appear as a bare
body (`-3`) or as the first command result (`[-3]`). It also retries HTTP
`429`, `500`, `502`, `503`, and `504`, with bounded exponential backoff.

### Hashcash / HTTP 402 During Login

MEGA can answer login-related API calls with HTTP `402 Payment Required` and an
`X-Hashcash` response header. In this context it is not a billing error. It is a
proof-of-work challenge.

The retry behavior is:

1. Send the original `/cs` POST.
2. If the response is HTTP `402` and includes `X-Hashcash`, solve the challenge.
3. Retry the exact same POST with:

```text
X-Hashcash: <solution>
```

The current challenge format observed by this client is:

```text
1:<easiness>:<timestamp>:<token>
```

The solution format is:

```text
1:<token>:<prefix>
```

Solver used by this repo:

1. Split the challenge by `:`.
2. Require version `1`.
3. Decode `<token>` as base64url.
4. Build a buffer of `4 + 262144 * 48` bytes.
5. The first 4 bytes are a mutable prefix, initially zero.
6. Each 48-byte block after the prefix is the first 48 bytes of the decoded
   token.
7. Compute:

```text
baseVal = ((easiness & 63) << 1) + 1
shifts = (easiness >> 6) * 7 + 3
threshold = min(baseVal << shifts, 0xffffffff)
```

8. SHA-256 the whole buffer.
9. Read the first four hash bytes as a big-endian uint32.
10. If that value is less than or equal to `threshold`, return the solution.
11. Otherwise increment the 4-byte prefix as a little-endian counter and retry.

The CLI handles this inside `apiClient.call`, so all API commands can benefit
from it, but it is mainly expected during account login.

### Encoding

transfer.it uses URL-safe base64 without padding:

```go
base64.RawURLEncoding.EncodeToString(bytes)
base64.RawURLEncoding.DecodeString(text)
```

Do not use normal padded base64 unless you also normalize it. The strings
usually contain `-` and `_` and omit trailing `=`.

### Word Order

MEGA keys are represented as big-endian 32-bit words. Whenever this document
says "word", it means a `uint32` encoded in network byte order.

For example, a 128-bit AES key is four words:

```text
[k0, k1, k2, k3]
```

Serialized bytes are:

```text
bigendian(k0) || bigendian(k1) || bigendian(k2) || bigendian(k3)
```

See `wordsToBytes` and `bytesToWords` in `script.go`.

### Transfer Handles and Node Handles

A transfer link looks like:

```text
https://transfer.it/t/<xh>
```

`xh` is the transfer handle. The code extracts it from `/t/<xh>`.

Each file or folder in the transfer has a node handle:

```json
{
  "h": "nodeHandle",
  "p": "parentHandle",
  "t": 0
}
```

Node type values:

| `t` | Meaning |
| --- | --- |
| `0` | File |
| `1` | Folder |

The root folder node usually has no parent (`p` is empty or absent). Child
folders and files point at their parent handle through `p`.

## Download API

Download has four phases:

1. Parse the transfer handle from the URL.
2. Fetch public transfer metadata with `xi`.
3. If needed, derive and validate the password token with `xv`.
4. Fetch the node tree with `f`, decrypt node names, then download each file
   with `GET /cs/g`.

The direct file download endpoint returns the actual file bytes. The Go client
does not decrypt downloaded bytes after receiving them.

### `xi`: Public Transfer Info

Endpoint:

```text
POST https://bt7.api.mega.co.nz/cs?id=<id>
```

Payload:

```json
[
  {
    "a": "xi",
    "xh": "<transfer-handle>"
  }
]
```

Example response shape:

```json
[
  {
    "pw": 1,
    "t": "VGl0bGU",
    "m": "TWVzc2FnZQ",
    "z": "zipNodeHandle",
    "zp": 123456,
    "size": [123456, 1, 0, 0, 0]
  }
]
```

Known fields:

| Field | Meaning |
| --- | --- |
| `pw` | Non-zero means the transfer requires a password token |
| `t` | Base64url title text |
| `m` | Base64url message text |
| `z` | Zip node/handle used by the web UI for batch download, if present |
| `zp` | Zip size, if present |
| `size` | Transfer size summary; observed as bytes/files/folders plus extra counters |

The title and message are not encrypted in the public metadata response. Decode
them with raw URL-safe base64 and interpret the result as UTF-8.

Implemented by `getTransferInfo` in `script.go`.

### Password Token Derivation

The API does not send the plaintext password. It sends a derived token.

Algorithm:

1. Base64url-decode the transfer handle `xh`.
2. Take the last 6 decoded bytes.
3. Repeat those 6 bytes three times to create an 18-byte salt.
4. Trim whitespace from the user-supplied password.
5. Run PBKDF2-HMAC-SHA256 with 100000 iterations and 32 output bytes.
6. Base64url-encode the 32-byte result without padding.

Pseudocode:

```text
raw = base64url_decode_no_padding(xh)
salt_part = raw[len(raw)-6:]
salt = salt_part || salt_part || salt_part
key = PBKDF2_HMAC_SHA256(trim(password), salt, 100000, 32)
token = base64url_encode_no_padding(key)
```

Go equivalent:

```go
raw, _ := base64.RawURLEncoding.DecodeString(xh)
saltPart := raw[len(raw)-6:]
salt := append(append(append([]byte{}, saltPart...), saltPart...), saltPart...)
key := pbkdf2SHA256([]byte(strings.TrimSpace(password)), salt, 100000, 32)
token := base64.RawURLEncoding.EncodeToString(key)
```

Implemented by `deriveTransferPassword` in `script.go`.

### `xv`: Validate Password Token

Endpoint:

```text
POST https://bt7.api.mega.co.nz/cs?id=<id>
```

Payload:

```json
[
  {
    "a": "xv",
    "xh": "<transfer-handle>",
    "pw": "<derived-password-token>"
  }
]
```

Successful response:

```json
[1]
```

Invalid password responses are usually negative, commonly `[-14]`.

The CLI validates the password before node listing so the user gets a direct
"invalid transfer password" error instead of a later node-fetch failure.

Implemented by `validateTransferPassword` in `script.go`.

### `f`: Fetch Transfer Node Tree

Endpoint without password:

```text
POST https://bt7.api.mega.co.nz/cs?id=<id>&x=<transfer-handle>
```

Endpoint with password:

```text
POST https://bt7.api.mega.co.nz/cs?id=<id>&x=<transfer-handle>&pw=<password-token>
```

Payload:

```json
[
  {
    "a": "f",
    "c": 1,
    "r": 1
  }
]
```

Response shape:

```json
[
  {
    "f": [
      {
        "h": "rootHandle",
        "t": 1,
        "a": "encryptedAttributes",
        "k": "nodeKey"
      },
      {
        "h": "fileHandle",
        "p": "rootHandle",
        "t": 0,
        "a": "encryptedAttributes",
        "k": "nodeKey",
        "s": 12345,
        "ts": 1760000000
      }
    ]
  }
]
```

Important request fields:

| Field | Meaning |
| --- | --- |
| `a: "f"` | Fetch nodes |
| `c: 1` | Request cache/node payload style used by the web client |
| `r: 1` | Recursive listing, required for directory transfers |

Important response fields:

| Field | Meaning |
| --- | --- |
| `h` | Node handle |
| `p` | Parent node handle |
| `t` | Node type: `0` file, `1` folder |
| `a` | AES-CBC encrypted attributes |
| `k` | Node key, base64url encoded |
| `s` | File size in bytes |
| `ts` | Node timestamp |

After `f`, the client decrypts each node's attributes to get the display name.
Then it reconstructs paths by walking `p` parent links back toward the root.

Implemented by `fetchNodes`, `decryptNodeName`, and `buildNodePath` in
`script.go`.

### Node Attribute Decryption

Node names are stored in encrypted attributes, not in plaintext node fields.

The encrypted attribute string `a` is:

```text
base64url_no_padding(AES-CBC-Encrypt(attrAESKey, zeroIV, padded("MEGA" || json)))
```

To decrypt:

1. Base64url-decode `a`.
2. Base64url-decode `k` into words.
3. Build the attribute AES key:
   - folder key, 4 words: use `[k0, k1, k2, k3]`
   - file key, 8 words: use `[k0 ^ k4, k1 ^ k5, k2 ^ k6, k3 ^ k7]`
4. AES-CBC-decrypt with a zero IV.
5. Strip trailing NUL bytes.
6. Verify the result starts with `MEGA`.
7. JSON-decode the bytes after `MEGA`.

The JSON usually looks like:

```json
{
  "n": "filename.ext"
}
```

For root transfer folders created by this CLI, the JSON includes a timestamp:

```json
{
  "t": 1760000000,
  "n": "Transfer title"
}
```

Implemented by `decryptNodeName`, `encryptAttr`, and `attrAESKey` in
`script.go`.

### `GET /cs/g`: Download File Bytes

Endpoint:

```text
GET https://bt7.api.mega.co.nz/cs/g?x=<transfer-handle>&n=<node-handle>&fn=<urlencoded-filename>
```

Password-protected endpoint:

```text
GET https://bt7.api.mega.co.nz/cs/g?x=<transfer-handle>&n=<node-handle>&fn=<urlencoded-filename>&pw=<password-token>
```

Required headers:

```text
User-Agent: Mozilla/5.0
Referer: https://transfer.it/t/<transfer-handle>
Origin: https://transfer.it
```

Resume header:

```text
Range: bytes=<already-downloaded-size>-
```

Important behavior:

- The endpoint may redirect to a storage host. Follow redirects.
- Without the `Referer` and `Origin` headers, transfer.it can return the
  landing page instead of the file.
- A normal full download returns HTTP `200`.
- A resumed download returns HTTP `206`.
- If a `Range` request receives HTTP `200`, the server ignored the range and
  the client should restart the local file from byte 0.
- The response body is plaintext file data for transfer.it downloads. This is
  different from the lower-level MEGA file download model where clients often
  decrypt encrypted chunks themselves.
- After writing the file, the CLI recomputes the MEGA-style per-chunk MAC and
  final meta MAC from the plaintext bytes and the file node key. If verification
  fails after a resumed download, it retries once from byte 0. A same-size
  existing file is skipped only if this MAC verification succeeds.
- Browser downloads through the transfer.it web app can fail for reasons that
  do not affect this direct endpoint, especially when using VPN exit nodes that
  trigger transfer.it or MEGA edge anti-abuse/rate-limit behavior.

Implemented by `downloadNode`, `downloadNodeBytes`, and `verifyDownloadedFile`
in `script.go`.

## Upload API

Upload has these phases:

1. Create an anonymous MEGA session using `up` and `us`, or log in to a MEGA
   account using `us0` and `us`.
2. Create a transfer root with `xn`.
3. For directories, create remote folder nodes with `xp`.
4. For every file:
   - request an upload URL with `u`
   - encrypt and upload chunks to that upload URL
   - finalize the uploaded file node with `xp`
5. Set link metadata with `xm`.
6. For "Send files", add recipients and optional schedule with `xr`.
7. Close/finalize the transfer with `xc`.

The "Create link" and "Send files" tabs are not separate upload protocols.
They use the same transfer creation and upload flow. "Send files" adds one or
more recipient calls through `xr`.

### `up`: Create Anonymous Account

Endpoint:

```text
POST https://g.api.mega.co.nz/cs?id=<id>
```

Payload:

```json
[
  {
    "a": "up",
    "k": "<encrypted-master-key>",
    "ts": "<self-check>"
  }
]
```

Response:

```json
["anonymousUserHandle"]
```

The CLI creates a temporary anonymous MEGA identity. It generates:

| Value | Size | Purpose |
| --- | --- | --- |
| `masterKey` | 4 words / 16 bytes | Session/account master key |
| `passwordKey` | 4 words / 16 bytes | Local key used to encrypt the master key |
| `ssc` | 4 words / 16 bytes | Self-check challenge |

`k` is:

```text
base64url_no_padding(AES-ECB(passwordKey, masterKey))
```

`ts` is:

```text
base64url_no_padding(ssc || AES-ECB(masterKey, ssc))
```

Go does not expose AES-ECB as a mode. The code implements the needed ECB block
operation by calling `block.Encrypt` or `block.Decrypt` on each 16-byte block.

Implemented by `createAnonymousSession` and `encryptWords` in `script.go`.

### `us`: Start Anonymous Session

Endpoint:

```text
POST https://g.api.mega.co.nz/cs?id=<id>
```

Payload:

```json
[
  {
    "a": "us",
    "user": "<anonymousUserHandle>"
  }
]
```

Response shape:

```json
[
  {
    "tsid": "<session-id-material>",
    "k": "<encrypted-master-key>"
  }
]
```

Client-side verification:

1. Base64url-decode response `k`.
2. AES-ECB-decrypt it with `passwordKey`.
3. Confirm the decrypted value equals the original `masterKey`.
4. Base64url-decode `tsid`.
5. Confirm it is 43 bytes.
6. AES-ECB-encrypt the first 16 bytes of `tsid` with the decrypted master key.
7. Confirm that encrypted block equals bytes `27:43` of decoded `tsid`.
8. Use `base64url_no_padding(decoded_tsid)` as the `sid` query value.

All upload and transfer-management calls after this point include:

```text
&sid=<sid>
```

Implemented by `createAnonymousSession` and `decryptWords` in `script.go`.

### Account Login: `us0` and `us`

Account mode uses a real MEGA account session instead of an anonymous session.
The transfer.it upload commands are otherwise the same: after a valid `sid` is
available, `xn`, `xp`, `u`, `xm`, `xr`, and `xc` are sent to the transfer API
with `&sid=<sid>`.

#### `us0`: Discover Login Method

Endpoint:

```text
POST https://g.api.mega.co.nz/cs?id=<id>
```

Payload:

```json
[
  {
    "a": "us0",
    "user": "user@example.com"
  }
]
```

Response for modern accounts:

```json
[
  {
    "s": "<salt>",
    "v": 2
  }
]
```

For `v: 2`, derive the password key and user hash like this:

```text
derived = PBKDF2-HMAC-SHA512(password, base64url_decode(s), 100000, 32)
passwordKey = derived[0:16]
userHash = base64url_no_padding(derived[16:32])
```

For old `v: 1` accounts, the client uses the historical MEGA AES key schedule:

1. Convert the password string to big-endian 32-bit words.
2. Start with words:

```text
[0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56]
```

3. Run 65536 rounds of AES-ECB over 4-word password blocks.
4. Build the email string hash by XORing email words into four hash words.
5. AES-ECB-encrypt those hash words 16384 times with the password key.
6. The `uh` value is base64url of words `[hash0, hash2]`.

The implementation supports both paths, but new accounts normally use `v: 2`.

#### `us`: Start Account Session

Endpoint:

```text
POST https://g.api.mega.co.nz/cs?id=<id>
```

Payload:

```json
[
  {
    "a": "us",
    "user": "user@example.com",
    "uh": "<user-hash>"
  }
]
```

If two-factor authentication is required, add:

```json
{
  "mfa": "123456"
}
```

Response shape for a full MEGA account:

```json
[
  {
    "k": "<encrypted-master-key>",
    "csid": "<encrypted-session-id>",
    "privk": "<encrypted-rsa-private-key>"
  }
]
```

To produce the final `sid`:

1. Decode `k`.
2. AES-ECB-decrypt it with `passwordKey` to get the 4-word master key.
3. Decode `privk`.
4. AES-ECB-decrypt it with the master key.
5. Parse the resulting MPI values as RSA `p`, `q`, `d`, and `u`.
6. Decode `csid` as an MPI.
7. Compute:

```text
plainSession = csid^d mod (p*q)
sid = base64url_no_padding(first 43 bytes of plainSession)
```

That `sid` can then be used as `&sid=<sid>` on the transfer API.

The CLI stores account state in:

```text
~/.config/transferit-cli/config.json
```

Stored fields:

| Field | Meaning |
| --- | --- |
| `email` | Saved MEGA account email |
| `password` | Optional plaintext password, only saved when requested |
| `sid` | Reusable MEGA session id |
| `updated_at` | Timestamp when the config was last saved |

The config file is written with mode `0600`. The decrypted account master key
is used only in memory during login and is not persisted. On Windows, the file
inherits its access-control list from `%AppData%`.

For `upload --account`, the CLI prefers the saved `sid` first. An explicit
`--account-password` forces a fresh login. If no saved session is available but
a saved password exists, the CLI logs in again and updates the saved `sid`. If
transfer creation returns API error `-15` for an invalid saved session, the CLI
refreshes the login, saves the new session, and retries transfer creation.

Implemented by `loginMegaAccount`, `getMegaLoginMethod`,
`completeMegaLogin`, `sidFromCSID`, `generateHashcashToken`, and the account
config helpers in `script.go`.

### `xn`: Create Transfer Root

Endpoint:

```text
POST https://bt7.api.mega.co.nz/cs?id=<id>&sid=<sid>
```

Payload:

```json
[
  {
    "a": "xn",
    "at": "<encrypted-root-attributes>",
    "k": "<root-folder-key>"
  }
]
```

Response:

```json
[
  [
    "<transfer-handle>",
    "<root-folder-handle>"
  ]
]
```

The root folder key is four random words. The root attributes are encrypted
with that key and usually contain the transfer title:

```json
{
  "t": 1760000000,
  "n": "Transfer title"
}
```

The resulting public link is:

```text
https://transfer.it/t/<transfer-handle>
```

Implemented by `createTransfer` in `script.go`.

### `xp`: Create Folder Nodes

Endpoint:

```text
POST https://bt7.api.mega.co.nz/cs?id=<id>&sid=<sid>
```

Payload:

```json
[
  {
    "a": "xp",
    "v": 3,
    "t": "<parent-folder-handle>",
    "n": [
      {
        "h": "xxxxxxxx",
        "t": 1,
        "a": "<encrypted-folder-attributes>",
        "k": "<folder-key>"
      }
    ]
  }
]
```

Response shape:

```json
[
  {
    "f": [
      {
        "h": "<created-folder-handle>"
      }
    ]
  }
]
```

Important fields:

| Field | Meaning |
| --- | --- |
| `a: "xp"` | Put/publish node into the transfer |
| `v: 3` | Transfer node publish protocol version used by the web app |
| `t` | Parent folder handle |
| `n` | Array of nodes to publish |
| `h: "xxxxxxxx"` | Placeholder handle for a new folder; server replaces it |
| `t: 1` inside node | Folder node type |
| `a` inside node | Encrypted folder attributes |
| `k` inside node | Folder key, base64url encoded |

Folder attributes normally contain:

```json
{
  "n": "folder-name"
}
```

For directory uploads, the CLI walks the local directory tree, creates all
folder nodes first, and stores a map from relative path to remote folder handle.
Empty directories are preserved because folder nodes are created even when they
contain no files.

Implemented by `createRemoteFolders` and `createRemoteFolder` in `script.go`.

### `u`: Request Upload URL

Endpoint:

```text
POST https://bt7.api.mega.co.nz/cs?id=<id>&sid=<sid>
```

Payload:

```json
[
  {
    "a": "u",
    "s": 123456,
    "ssl": 2
  }
]
```

Response:

```json
[
  {
    "p": "https://upload-host/path"
  }
]
```

Fields:

| Field | Meaning |
| --- | --- |
| `s` | Plaintext file size in bytes |
| `ssl: 2` | Ask for HTTPS upload URL |

The returned `p` URL is not a `/cs` endpoint. File chunks are posted directly
to it.

Implemented by `uploadFile` in `script.go`.

### Upload Chunk POST

Endpoint:

```text
POST <upload-url>/<chunk-offset>
User-Agent: Mozilla/5.0

<encrypted chunk bytes>
```

Example:

```text
POST https://upload-host/path/0
POST https://upload-host/path/131072
POST https://upload-host/path/393216
```

The offset is the plaintext byte offset of that chunk in the file.

Chunk sizes follow the MEGA upload pattern:

| Chunk index | Size |
| --- | --- |
| 1 | 128 KiB |
| 2 | 256 KiB |
| 3 | 384 KiB |
| 4 | 512 KiB |
| 5 | 640 KiB |
| 6 | 768 KiB |
| 7 | 896 KiB |
| 8 | 1024 KiB |
| 9+ | 1024 KiB |

If the file is smaller than the next chunk size, the final chunk is truncated to
the remaining size.

For an empty file, this implementation sends one zero-length chunk at offset
`0`. The upload server still returns a completion handle for the final chunk.

Intermediate chunk responses are usually empty. The final chunk response body
contains a completion handle. This CLI may upload non-final chunks in parallel,
but it waits to POST the final chunk until the earlier chunks complete so that
the completion handle is returned predictably. That handle is later supplied as
the file node `h` in `xp`.

Completion handles are URL-safe token strings and can begin with `-`. Do not
treat every upload response body starting with `-` as an error. Treat it as an
API error only when the whole response body is a negative integer, such as
`-3`.

Implemented by `getChunkSizes`, `uploadChunks`, `postUploadChunk`, and
`uploadFile` in `script.go`.

### File Upload Encryption

Every uploaded file gets a random six-word upload key:

```text
ukey = [k0, k1, k2, k3, n0, n1]
```

The AES key is:

```text
[k0, k1, k2, k3]
```

The nonce words are:

```text
[n0, n1]
```

Each plaintext chunk is encrypted with AES-CTR.

CTR key:

```text
AES key = words(k0, k1, k2, k3)
```

CTR initial counter for a chunk at byte offset `pos`:

```text
[n0, n1, floor(pos / 0x1000000000), floor(pos / 16)]
```

The counter words are serialized big-endian before passing them to AES-CTR.

Per-chunk MAC:

1. Pad the plaintext chunk with NUL bytes to a 16-byte boundary.
2. AES-CBC-encrypt the padded plaintext using the same AES key.
3. Use IV `[n0, n1, n0, n1]`.
4. The chunk MAC is the final encrypted 16-byte block.
5. An empty chunk uses sixteen zero bytes as its MAC.

A zero-length file contributes **no** chunk MAC at all. The upload still posts one
zero-length chunk to obtain the completion handle, but that chunk's MAC is excluded
from the condensation below, so an empty file's meta MAC is `[0, 0]`. Condensing the
synthetic chunk instead would yield `AES(k, 0)` and disagree with every other MEGA
client.

After all chunks are uploaded, combine the chunk MACs:

1. Start with a 16-byte zero block.
2. AES-CBC-encrypt each chunk MAC block with the file AES key and zero IV,
   carrying CBC state across MAC blocks.
3. Interpret the final 16-byte result as words `[m0, m1, m2, m3]`.
4. Compute the meta MAC:

```text
meta0 = m0 ^ m1
meta1 = m2 ^ m3
```

The final eight-word file key is:

```text
[
  k0 ^ n0,
  k1 ^ n1,
  k2 ^ meta0,
  k3 ^ meta1,
  n0,
  n1,
  meta0,
  meta1
]
```

This final file key is what is stored in the transfer node's `k` field.

Implemented by `encryptUploadChunk` and `buildFileKey` in `script.go`.

### `xp`: Finalize File Node

After all encrypted chunks are uploaded and the upload server returns a
completion handle, publish the file node with `xp`.

Endpoint:

```text
POST https://bt7.api.mega.co.nz/cs?id=<id>&sid=<sid>
```

Payload:

```json
[
  {
    "a": "xp",
    "v": 3,
    "t": "<parent-folder-handle>",
    "n": [
      {
        "t": 0,
        "h": "<upload-completion-handle>",
        "a": "<encrypted-file-attributes>",
        "k": "<final-file-key>"
      }
    ]
  }
]
```

Response shape:

```json
[
  {
    "f": [
      {
        "h": "<created-file-node-handle>"
      }
    ]
  }
]
```

Important fields:

| Field | Meaning |
| --- | --- |
| `t` in the outer object | Parent folder handle |
| `t: 0` inside node | File node type |
| `h` inside node | Upload completion handle returned by the final chunk POST |
| `a` inside node | Encrypted file attributes |
| `k` inside node | Final eight-word file key |

File attributes usually contain:

```json
{
  "n": "filename.ext"
}
```

For transfer.it uploads, the file key is stored directly as raw base64url key
material. This is different from normal logged-in MEGA node storage, where node
keys may be encrypted to the user's master key.

Implemented by `uploadFile` in `script.go`.

### `xm`: Set Transfer Metadata

Endpoint:

```text
POST https://bt7.api.mega.co.nz/cs?id=<id>&sid=<sid>
```

Payload:

```json
[
  {
    "a": "xm",
    "xh": "<transfer-handle>",
    "t": "VGl0bGU",
    "m": "TWVzc2FnZQ",
    "se": "sender@example.com",
    "pw": "<derived-password-token>",
    "e": 7776000
  }
]
```

Successful response:

```json
[0]
```

All fields except `a` and `xh` are optional.

Fields used by this implementation:

| Field | Meaning |
| --- | --- |
| `t` | Transfer title, base64url UTF-8 |
| `m` | Transfer message, base64url UTF-8 |
| `se` | Sender email address from "Your email (optional)" |
| `pw` | Derived password token from the same algorithm used for downloads |
| `e` | Expiry in seconds |

Expiry values used by the UI and CLI:

| UI value | `e` value |
| --- | --- |
| 7 days | `604800` |
| 30 days | `2592000` |
| 90 days | `7776000` |

The CLI's `--expire 0` means "omit `e`". Its default is `--expire 90`, so by
default it sends `e: 7776000`.

Implemented by `setTransferOptions` in `script.go`.

### `xr`: Add Recipient / Send Files

Endpoint:

```text
POST https://bt7.api.mega.co.nz/cs?id=<id>&sid=<sid>
```

Payload without schedule:

```json
[
  {
    "a": "xr",
    "xh": "<transfer-handle>",
    "e": "recipient@example.com"
  }
]
```

Payload with scheduled send time:

```json
[
  {
    "a": "xr",
    "xh": "<transfer-handle>",
    "e": "recipient@example.com",
    "s": 1893456000
  }
]
```

Fields:

| Field | Meaning |
| --- | --- |
| `e` | Recipient email address from "Email to" |
| `s` | Optional Unix timestamp in seconds for "Send date and time" |

The CLI calls `xr` once per recipient. A non-negative response is treated as
success. A negative response is treated as failure.

Implemented by `setTransferRecipient` and `parseSchedule` in `script.go`.

### `xc`: Close / Finalize Transfer

Endpoint:

```text
POST https://bt7.api.mega.co.nz/cs?id=<id>&sid=<sid>
```

Payload:

```json
[
  {
    "a": "xc",
    "xh": "<transfer-handle>"
  }
]
```

Successful response:

```json
[0]
```

Call this after:

1. Creating the root transfer with `xn`.
2. Creating folders with `xp`, if any.
3. Uploading and publishing all files with `u`, chunk POSTs, and `xp`.
4. Setting metadata with `xm`.
5. Adding recipients with `xr`, if any.

After `xc`, the public link is ready and recipient emails are queued by the
service.

Implemented by `closeTransfer` in `script.go`.

## End-to-End Download Flow

### Public Link

```text
input: https://transfer.it/t/<xh>

1. xh = parse /t/<xh>
2. POST bt7 /cs: [{ "a": "xi", "xh": xh }]
3. POST bt7 /cs?x=<xh>: [{ "a": "f", "c": 1, "r": 1 }]
4. For each node:
   a. base64url-decode node.k
   b. decrypt node.a
   c. extract attr.n
5. Create local folders from folder nodes.
6. For each file node:
   GET bt7 /cs/g?x=<xh>&n=<node.h>&fn=<node.name>
   with Referer and Origin headers.
```

### Password-Protected Link

```text
input: https://transfer.it/t/<xh>, password

1. xh = parse /t/<xh>
2. POST bt7 /cs: [{ "a": "xi", "xh": xh }]
3. If xi.pw != 0:
   a. token = deriveTransferPassword(xh, password)
   b. POST bt7 /cs: [{ "a": "xv", "xh": xh, "pw": token }]
   c. require response [1]
4. POST bt7 /cs?x=<xh>&pw=<token>: [{ "a": "f", "c": 1, "r": 1 }]
5. Decrypt node attributes and reconstruct paths.
6. For each file node:
   GET bt7 /cs/g?x=<xh>&n=<node.h>&fn=<node.name>&pw=<token>
   with Referer and Origin headers.
```

## End-to-End Upload Flow

### Create Link Mode

```text
input: local files/directories, title, message, sender email, password, expiry

1. Generate masterKey, passwordKey, and self-check challenge.
2. POST g /cs: up
3. POST g /cs: us
4. sid = verified session id from us response.
5. POST bt7 /cs?sid=<sid>: xn
   -> receives xh and root folder handle.
6. Walk input paths.
7. For every directory:
   POST bt7 /cs?sid=<sid>: xp folder node
8. For every file:
   a. POST bt7 /cs?sid=<sid>: u
      -> receives upload URL.
   b. Generate six-word file upload key.
   c. Split file into MEGA chunk sizes.
   d. Encrypt each chunk with AES-CTR.
   e. POST each encrypted chunk to <upload-url>/<offset>.
   f. Save final upload completion handle.
   g. Compute final eight-word file key.
   h. Encrypt file attributes.
   i. POST bt7 /cs?sid=<sid>: xp file node.
9. POST bt7 /cs?sid=<sid>: xm metadata/password/expiry.
10. POST bt7 /cs?sid=<sid>: xc.
11. Link is https://transfer.it/t/<xh>.
```

### Send Files Mode

Send-files mode is create-link mode plus recipients:

```text
1. Run the same steps as Create Link Mode through xm.
2. For every recipient:
   POST bt7 /cs?sid=<sid>: xr
3. POST bt7 /cs?sid=<sid>: xc.
```

If a send date/time is set, include `s` in each `xr` command as a Unix
timestamp in seconds.

## Directory Behavior

transfer.it represents directories as folder nodes in the same node tree as
files. The CLI preserves directories by doing two things:

1. Upload: it walks each input directory recursively, creates every folder node
   with `xp`, then uploads each file into the correct parent folder handle.
2. Download: it fetches all nodes with `f` and `r: 1`, reconstructs relative
   paths from parent handles, creates all folders first, then downloads files.

Local path rules in this implementation:

- Each uploaded directory remains as a top-level directory in the transfer.
- Multiple input paths are allowed.
- Duplicate relative paths are rejected before upload.
- Special files such as devices, sockets, and symlinks are rejected.
- File and folder names are sanitized on download by replacing `/` and `\`
  with `_` and removing NUL bytes.

## Minimal Implementation Checklist

A developer reimplementing this in another language needs:

- HTTP client with redirect support.
- JSON array command sender for `/cs`.
- Raw URL-safe base64 with no padding.
- AES-ECB block encrypt/decrypt helper for keys and session checks.
- AES-CBC with zero IV for attributes.
- AES-CTR for upload chunks.
- PBKDF2-HMAC-SHA256 for transfer password tokens.
- Big-endian 32-bit word conversions.
- Recursive local directory traversal.
- Resume-capable file writer using HTTP `Range`.

The most important parts to copy exactly are:

- Password token salt derivation from `xh`.
- Attribute key derivation for 4-word folder keys and 8-word file keys.
- Upload chunk size schedule.
- Upload CTR counter words.
- Upload per-chunk MAC and final meta MAC.
- Required `Referer` and `Origin` headers for direct downloads.

## Function Map

Use this map to connect protocol concepts to the Go source:

| Protocol area | Go function |
| --- | --- |
| Parse transfer URL | `parseTransferHandle` |
| Send `/cs` command | `apiClient.call` |
| Public metadata `xi` | `getTransferInfo` |
| Password validation `xv` | `validateTransferPassword` |
| Node listing `f` | `fetchNodes` |
| Path reconstruction | `buildNodePath` |
| File download `GET /cs/g` | `downloadNode` |
| Anonymous session `up` / `us` | `createAnonymousSession` |
| Transfer creation `xn` | `createTransfer` |
| Folder publish `xp` | `createRemoteFolder` |
| Upload URL `u` | `uploadFile` |
| Upload chunk POST | `postUploadChunk` |
| Upload chunk encryption | `encryptUploadChunk` |
| Final file key | `buildFileKey` |
| File publish `xp` | `uploadFile` |
| Transfer metadata `xm` | `setTransferOptions` |
| Recipient/schedule `xr` | `setTransferRecipient` |
| Finalize transfer `xc` | `closeTransfer` |
| Attribute encryption/decryption | `encryptAttr`, `decryptNodeName`, `attrAESKey` |
| Base64 helpers | `b64Encode`, `b64Decode` |
| Word conversion helpers | `wordsToBytes`, `bytesToWords` |

## Example Raw Requests

### Fetch Metadata

```http
POST /cs?id=1760000000001 HTTP/1.1
Host: bt7.api.mega.co.nz
Content-Type: application/json
User-Agent: Mozilla/5.0

[{"a":"xi","xh":"TRANSFER_HANDLE"}]
```

### Fetch Nodes

```http
POST /cs?id=1760000000002&x=TRANSFER_HANDLE&pw=PASSWORD_TOKEN HTTP/1.1
Host: bt7.api.mega.co.nz
Content-Type: application/json
User-Agent: Mozilla/5.0

[{"a":"f","c":1,"r":1}]
```

### Download File

```http
GET /cs/g?x=TRANSFER_HANDLE&n=NODE_HANDLE&fn=file.bin&pw=PASSWORD_TOKEN HTTP/1.1
Host: bt7.api.mega.co.nz
User-Agent: Mozilla/5.0
Referer: https://transfer.it/t/TRANSFER_HANDLE
Origin: https://transfer.it
```

### Create Transfer

```http
POST /cs?id=1760000000003&sid=SID HTTP/1.1
Host: bt7.api.mega.co.nz
Content-Type: application/json
User-Agent: Mozilla/5.0

[{"a":"xn","at":"ENCRYPTED_ATTRS","k":"ROOT_FOLDER_KEY"}]
```

### Set Metadata

```http
POST /cs?id=1760000000004&sid=SID HTTP/1.1
Host: bt7.api.mega.co.nz
Content-Type: application/json
User-Agent: Mozilla/5.0

[{"a":"xm","xh":"TRANSFER_HANDLE","t":"VGl0bGU","m":"TWVzc2FnZQ","e":604800}]
```

## Security Notes

- Password-protected transfers do not send the plaintext password to the API.
  They send the PBKDF2-derived token.
- Anyone with the transfer link and, if required, the password can fetch the
  node tree and download the files.
- This CLI does not persist the anonymous upload session. It creates a session,
  uploads, finalizes, and exits.
- This document describes observed behavior, not a contractual API. transfer.it
  can change hosts, fields, required headers, or command semantics at any time.
