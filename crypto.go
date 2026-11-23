package main

import (
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
	"fmt"
	"io"
	"math/big"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

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

func ukeyFromFileKey(fileKey []uint32) ([]uint32, error) {
	if len(fileKey) < 8 {
		return nil, fmt.Errorf("file key is too short: %d words", len(fileKey))
	}
	return []uint32{
		fileKey[0] ^ fileKey[4],
		fileKey[1] ^ fileKey[5],
		fileKey[2] ^ fileKey[6],
		fileKey[3] ^ fileKey[7],
		fileKey[4],
		fileKey[5],
	}, nil
}

func computeFileKeyFromReader(f io.ReaderAt, fileKey []uint32, size int64) ([]uint32, error) {
	macWriter, err := newStreamingFileMAC(fileKey, size)
	if err != nil {
		return nil, err
	}
	if size > 0 {
		buf := make([]byte, 256*1024)
		if _, err := io.CopyBuffer(macWriter, io.NewSectionReader(f, 0, size), buf); err != nil {
			return nil, err
		}
	}
	return macWriter.FileKey()
}

// streamingFileMAC computes a MEGA file key's meta-MAC in one streaming pass over
// sequential plaintext bytes, using fixed memory regardless of file size.
type streamingFileMAC struct {
	ukey         [6]uint32
	block        cipher.Block
	macIV        [aes.BlockSize]byte
	chunks       []chunkSize
	chunkIdx     int
	chunkPos     int
	chunkEnc     cipher.BlockMode
	tail         [aes.BlockSize]byte
	tailLen      int
	lastBlock    [aes.BlockSize]byte
	metaEnc      cipher.BlockMode
	metaData     [aes.BlockSize]byte
	scratch      [4096]byte
	totalWritten int64
	expectedSize int64
}

func newStreamingFileMAC(fileKey []uint32, size int64) (*streamingFileMAC, error) {
	ukey, err := ukeyFromFileKey(fileKey)
	if err != nil {
		return nil, err
	}
	var keyBytes [aes.BlockSize]byte
	putWords(keyBytes[:], ukey[:4])
	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		return nil, err
	}
	m := &streamingFileMAC{
		block:        block,
		chunks:       getChunkSizes(size),
		expectedSize: size,
	}
	copy(m.ukey[:], ukey)
	putWords(m.macIV[:], []uint32{ukey[4], ukey[5], ukey[4], ukey[5]})
	var zeroIV [aes.BlockSize]byte
	m.metaEnc = cipher.NewCBCEncrypter(block, zeroIV[:])
	if len(m.chunks) > 0 {
		m.chunkEnc = cipher.NewCBCEncrypter(block, m.macIV[:])
	}
	return m, nil
}

func (m *streamingFileMAC) Write(p []byte) (int, error) {
	written := len(p)
	for len(p) > 0 {
		if m.chunkIdx >= len(m.chunks) {
			m.totalWritten += int64(len(p))
			return written, nil
		}
		ch := m.chunks[m.chunkIdx]
		take := min(len(p), ch.size-m.chunkPos)
		slice := p[:take]
		p = p[take:]
		m.chunkPos += take
		m.totalWritten += int64(take)

		if m.tailLen > 0 {
			n := copy(m.tail[m.tailLen:], slice)
			m.tailLen += n
			slice = slice[n:]
			if m.tailLen == aes.BlockSize {
				m.chunkEnc.CryptBlocks(m.lastBlock[:], m.tail[:])
				m.tailLen = 0
			}
		}
		if full := (len(slice) / aes.BlockSize) * aes.BlockSize; full > 0 {
			for off := 0; off < full; {
				n := min(full-off, len(m.scratch))
				m.chunkEnc.CryptBlocks(m.scratch[:n], slice[off:off+n])
				off += n
				if off == full {
					copy(m.lastBlock[:], m.scratch[n-aes.BlockSize:n])
				}
			}
			slice = slice[full:]
		}
		if len(slice) > 0 {
			m.tailLen = copy(m.tail[:], slice)
		}

		if m.chunkPos == ch.size {
			if m.tailLen > 0 {
				clear(m.tail[m.tailLen:])
				m.chunkEnc.CryptBlocks(m.lastBlock[:], m.tail[:])
				m.tailLen = 0
			}
			m.metaEnc.CryptBlocks(m.metaData[:], m.lastBlock[:])
			m.chunkIdx++
			m.chunkPos = 0
			if m.chunkIdx < len(m.chunks) {
				m.chunkEnc = cipher.NewCBCEncrypter(m.block, m.macIV[:])
			}
		}
	}
	return written, nil
}

func (m *streamingFileMAC) FileKey() ([]uint32, error) {
	if m.totalWritten != m.expectedSize || m.chunkIdx != len(m.chunks) {
		return nil, fmt.Errorf("size mismatch: hashed %d bytes, want %d bytes", m.totalWritten, m.expectedSize)
	}
	t0 := binary.BigEndian.Uint32(m.metaData[0:4])
	t1 := binary.BigEndian.Uint32(m.metaData[4:8])
	t2 := binary.BigEndian.Uint32(m.metaData[8:12])
	t3 := binary.BigEndian.Uint32(m.metaData[12:16])
	metaMac0 := t0 ^ t1
	metaMac1 := t2 ^ t3
	return []uint32{
		m.ukey[0] ^ m.ukey[4],
		m.ukey[1] ^ m.ukey[5],
		m.ukey[2] ^ metaMac0,
		m.ukey[3] ^ metaMac1,
		m.ukey[4],
		m.ukey[5],
		metaMac0,
		metaMac1,
	}, nil
}

func (m *streamingFileMAC) Verify(expected []uint32) error {
	computed, err := m.FileKey()
	if err != nil {
		return err
	}
	if !slices.Equal(computed, expected) {
		return errIntegrityMismatch
	}
	return nil
}

// computeChunkMAC computes one chunk's AES-CBC-MAC without mutating chunk.
// scratch must have length > 0 and be a multiple of aes.BlockSize; keeping it
// small (e.g. 4 KiB) keeps the discarded CBC output inside L1 cache.
func computeChunkMAC(block cipher.Block, iv, chunk, scratch []byte) [aes.BlockSize]byte {
	var mac [aes.BlockSize]byte
	if len(chunk) == 0 {
		return mac
	}
	enc := cipher.NewCBCEncrypter(block, iv)
	full := (len(chunk) / aes.BlockSize) * aes.BlockSize
	lastN := 0
	for off := 0; off < full; {
		n := min(full-off, len(scratch))
		enc.CryptBlocks(scratch[:n], chunk[off:off+n])
		off += n
		lastN = n
	}
	if rem := len(chunk) - full; rem > 0 {
		var tail [aes.BlockSize]byte
		copy(tail[:], chunk[full:])
		enc.CryptBlocks(tail[:], tail[:])
		return tail
	}
	copy(mac[:], scratch[lastN-aes.BlockSize:lastN])
	return mac
}

// chunkMACs produces the per-chunk CBC-MACs for chunks read from f without
// running AES-CTR or allocating per-chunk buffers.
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
	var iv [aes.BlockSize]byte
	putWords(iv[:], []uint32{ukey[4], ukey[5], ukey[4], ukey[5]})
	largest := 0
	for _, ch := range chunks {
		if ch.size > largest {
			largest = ch.size
		}
	}
	readBuf := make([]byte, largest)
	var macScratch [4096]byte
	macBacking := make([]byte, len(chunks)*aes.BlockSize)
	macs := make([][]byte, len(chunks))
	for i, ch := range chunks {
		dst := macBacking[i*aes.BlockSize : (i+1)*aes.BlockSize]
		if ch.size > 0 {
			plain := readBuf[:ch.size]
			if _, err := f.ReadAt(plain, ch.position); err != nil {
				return nil, err
			}
			mac := computeChunkMAC(block, iv[:], plain, macScratch[:])
			copy(dst, mac[:])
		}
		macs[i] = dst
	}
	return macs, nil
}

// encryptChunkInto encrypts plain into enc (same length) with AES-CTR and returns
// the chunk's CBC-MAC without mutating plain or allocating on the heap.
func encryptChunkInto(block cipher.Block, ukey []uint32, macIV, plain, enc, macScratch []byte, offset int64) [aes.BlockSize]byte {
	var ctrIV [aes.BlockSize]byte
	binary.BigEndian.PutUint32(ctrIV[0:4], ukey[4])
	binary.BigEndian.PutUint32(ctrIV[4:8], ukey[5])
	binary.BigEndian.PutUint32(ctrIV[8:12], uint32(uint64(offset)/0x1000000000))
	binary.BigEndian.PutUint32(ctrIV[12:16], uint32(offset/16))
	cipher.NewCTR(block, ctrIV[:]).XORKeyStream(enc, plain)
	return computeChunkMAC(block, macIV, plain, macScratch)
}

func encryptUploadChunk(chunk []byte, ukey []uint32, offset int64) ([]byte, []byte, error) {
	if len(ukey) < 6 {
		return nil, nil, fmt.Errorf("upload key is too short: %d words", len(ukey))
	}
	block, err := aes.NewCipher(wordsToBytes(ukey[:4]))
	if err != nil {
		return nil, nil, err
	}
	var macIV [aes.BlockSize]byte
	putWords(macIV[:], []uint32{ukey[4], ukey[5], ukey[4], ukey[5]})
	encrypted := make([]byte, len(chunk))
	var macScratch [4096]byte
	mac := encryptChunkInto(block, ukey, macIV[:], chunk, encrypted, macScratch[:], offset)
	outMAC := make([]byte, aes.BlockSize)
	copy(outMAC, mac[:])
	return encrypted, outMAC, nil
}

func buildFileKey(ukey []uint32, macs [][]byte) ([]uint32, error) {
	key := wordsToBytes(ukey[:4])
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var macData [aes.BlockSize]byte
	var zeroIV [aes.BlockSize]byte
	enc := cipher.NewCBCEncrypter(block, zeroIV[:])
	for _, mac := range macs {
		enc.CryptBlocks(macData[:], mac)
	}
	t := bytesToWords(macData[:])
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

func getChunkSizes(size int64) []chunkSize {
	if size <= 0 {
		return nil
	}
	const rampBytes = 36 * 131072 // sum(1..8) * 128 KiB
	capHint := 8
	if size > rampBytes {
		capHint += int((size - rampBytes + 1048575) / 1048576)
	}
	chunks := make([]chunkSize, 0, capHint)
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
	salt := make([]byte, 0, 18)
	salt = append(salt, saltPart...)
	salt = append(salt, saltPart...)
	salt = append(salt, saltPart...)
	key, err := pbkdf2.Key(sha256.New, strings.TrimSpace(password), salt, 100000, 32)
	if err != nil {
		return "", err
	}
	return b64Encode(key), nil
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
		copy(blockKey[:], words[i:min(i+4, len(words))])
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

func generateHashcashToken(ctx context.Context, challenge string) (string, error) {
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

	prefix, ok := searchHashcashPrefix(ctx, token[:hashcashChunkSize], threshold)
	if !ok {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("hashcash challenge too hard (easiness %d): no solution within %d attempts", easiness, hashcashMaxAttempts)
	}
	return fmt.Sprintf("1:%s:%s", tokenText, b64Encode(prefix)), nil
}

// searchHashcashPrefix looks for a 4-byte prefix whose SHA-256 over the repeated
// token falls under threshold. Workers share one 64-byte-aligned 192 KiB rotated
// token block (hot in L2 cache, zero unaligned copies in sha256.Write) instead of
// allocating 12 MiB per worker.
func searchHashcashPrefix(ctx context.Context, token []byte, threshold uint64) ([]byte, bool) {
	workers := min(max(runtime.NumCPU(), 1), 16)

	// The stream is: prefix (4B) || token (48B) * 262144.
	// Block 0 (64B) is prefix (4B) || token (48B) || token[:12] (12B), leaving
	// the remaining stream aligned on 64B boundaries as repetitions of rotToken =
	// token[12:48] || token[:12].
	const (
		rotBlockChunks = 4096 // 192 KiB: multiple of both 48 and 64, fits in L2 cache
		rotBlockBytes  = rotBlockChunks * hashcashChunkSize
		fullRotWrites  = hashcashIterations/rotBlockChunks - 1     // 63
		tailBytes      = rotBlockBytes - (64 - hashcashPrefixSize) // 196548
	)
	rotBlock := make([]byte, rotBlockBytes)
	copy(rotBlock, token[12:hashcashChunkSize])
	copy(rotBlock[hashcashChunkSize-12:], token[:12])
	for n := hashcashChunkSize; n < len(rotBlock); n *= 2 {
		copy(rotBlock[n:], rotBlock[:n])
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
			h := sha256.New()
			var firstBlock [64]byte
			copy(firstBlock[hashcashPrefixSize:], token[:hashcashChunkSize])
			copy(firstBlock[hashcashPrefixSize+hashcashChunkSize:], token[:12])
			var sum [sha256.Size]byte
			for counter := start; !found.Load() && ctx.Err() == nil; counter += uint32(workers) {
				if atomic.AddInt64(&remaining, -1) < 0 {
					return
				}
				// The reference implementation increments the prefix bytes low-first,
				// which is a little-endian uint32 counter starting at zero.
				binary.LittleEndian.PutUint32(firstBlock[:hashcashPrefixSize], counter)
				h.Reset()
				_, _ = h.Write(firstBlock[:])
				for i := 0; i < fullRotWrites; i++ {
					_, _ = h.Write(rotBlock)
				}
				_, _ = h.Write(rotBlock[:tailBytes])
				h.Sum(sum[:0])
				if uint64(binary.BigEndian.Uint32(sum[:4])) <= threshold {
					mu.Lock()
					if solution == nil {
						solution = append([]byte(nil), firstBlock[:hashcashPrefixSize]...)
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

func randomWords(n int) ([]uint32, error) {
	buf := make([]byte, n*4)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return bytesToWords(buf), nil
}

func putWords(dst []byte, words []uint32) {
	for i, w := range words {
		binary.BigEndian.PutUint32(dst[i*4:], w)
	}
}

func wordsToBytes(words []uint32) []byte {
	buf := make([]byte, len(words)*4)
	putWords(buf, words)
	return buf
}

func bytesToWords(buf []byte) []uint32 {
	words := make([]uint32, len(buf)/4)
	for i := range words {
		words[i] = binary.BigEndian.Uint32(buf[i*4:])
	}
	return words
}

func stringToWords(s string) []uint32 {
	data := []byte(s)
	if rem := len(data) % 4; rem != 0 {
		data = append(data, make([]byte, 4-rem)...)
	}
	return bytesToWords(data)
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
