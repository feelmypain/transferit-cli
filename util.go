package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

// reorderFlagsFirst moves flags known to fs ahead of positional arguments so
// callers can place flags after URLs or file paths (e.g. "upload file --title x").
// Everything from "--" onward stays in the positional section unchanged.
func reorderFlagsFirst(fs *flag.FlagSet, args []string) []string {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			trimmed := strings.TrimPrefix(arg, "--")
			if trimmed == arg {
				trimmed = strings.TrimPrefix(arg, "-")
			}
			name, _, hasEq := strings.Cut(trimmed, "=")
			f := fs.Lookup(name)
			flags = append(flags, arg)
			if f != nil && !hasEq && i+1 < len(args) {
				bf, ok := f.Value.(interface{ IsBoolFlag() bool })
				if !ok || !bf.IsBoolFlag() {
					i++
					flags = append(flags, args[i])
				}
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	if len(positionals) > 0 {
		flags = append(flags, "--")
		flags = append(flags, positionals...)
	}
	return flags
}

func promptLine(label string) (string, error) {
	fmt.Print(label)
	line, err := stdinReader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func promptSecret(ctx context.Context, label string) (string, error) {
	fmt.Print(label)
	if stdinReader == defaultStdinReader {
		if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
			oldState, stateErr := term.GetState(fd)
			type result struct {
				pw  []byte
				err error
			}
			ch := make(chan result, 1)
			go func() {
				pw, err := term.ReadPassword(fd)
				ch <- result{pw: pw, err: err}
			}()
			select {
			case res := <-ch:
				fmt.Println()
				if res.err != nil {
					return "", res.err
				}
				return string(res.pw), nil
			case <-ctx.Done():
				if stateErr == nil {
					_ = term.Restore(fd, oldState)
				}
				fmt.Println()
				return "", ctx.Err()
			}
		}
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	fmt.Println()
	return strings.TrimRight(line, "\r\n"), nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
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

func safeName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unnamed"
	}
	s = strings.Map(func(r rune) rune {
		switch r {
		case 0:
			return -1
		case '/', '\\', '<', '>', ':', '"', '|', '?', '*':
			return '_'
		}
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
	stem, _, _ := strings.Cut(s, ".")
	base := strings.TrimRight(strings.ToUpper(stem), " ")
	if isWindowsReservedName(base) || looksLikeWindowsShortName(base) {
		return "_" + s
	}
	return s
}

func isWindowsReservedName(base string) bool {
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CONIN$" || base == "CONOUT$" {
		return true
	}
	if len(base) < 4 || (!strings.HasPrefix(base, "COM") && !strings.HasPrefix(base, "LPT")) {
		return false
	}
	r, size := utf8.DecodeRuneInString(base[3:])
	if 3+size != len(base) {
		return false
	}
	return (r >= '1' && r <= '9') || r == '¹' || r == '²' || r == '³'
}

func looksLikeWindowsShortName(base string) bool {
	tilde := strings.LastIndexByte(base, '~')
	if tilde < 1 || tilde == len(base)-1 {
		return false
	}
	prefixLength := utf8.RuneCountInString(base[:tilde])
	if prefixLength < 1 || prefixLength > 6 {
		return false
	}
	for i := tilde + 1; i < len(base); i++ {
		if base[i] < '0' || base[i] > '9' {
			return false
		}
	}
	return true
}

func copyWithProgress(dst io.Writer, src io.Reader, done, total int64) error {
	buf := make([]byte, 1024*1024)
	start := time.Now()
	nextPrint := start
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
