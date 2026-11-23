package main

import (
	"context"
	"crypto/aes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func runAccount(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		accountUsage()
		return nil
	}
	switch args[0] {
	case "login":
		return runAccountLogin(ctx, args[1:])
	case "status":
		return runAccountStatus(args[1:])
	case "logout":
		return runAccountLogout(args[1:])
	default:
		return fmt.Errorf("unknown account command %q", args[0])
	}
}

func accountUsage() {
	prog := programName()
	fmt.Fprintf(os.Stderr, `Usage:
  %[1]s account login --email EMAIL [--password PASS] [--save-password]
  %[1]s account status
  %[1]s account logout

Account options:
  --email EMAIL       MEGA account email
  --password PASS     MEGA account password; prompted if omitted
  --mfa CODE          two-factor authentication code, if the account requires it
  --save-password     save the account password in the local config file
  --no-save           validate login but do not save the session

The saved config path is:
  %s
`, prog, mustConfigPath())
}

func runAccountLogin(ctx context.Context, args []string) error {
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

	cfg, _, err := loadSavedConfig()
	if err != nil {
		return err
	}

	_, loginEmail, err := authenticateAccount(ctx, cfg, accountAuthOpts{
		email:        *email,
		password:     *password,
		mfa:          strings.TrimSpace(*mfa),
		savePassword: *savePassword,
		persist:      !*noSave,
	})
	if err != nil {
		return err
	}
	fmt.Printf("Login OK for %s.\n", loginEmail)
	if *noSave {
		return nil
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

type accountAuthOpts struct {
	email              string
	password           string
	mfa                string
	savePassword       bool
	allowSavedPassword bool
	persist            bool
	missingCredsErr    string
}

func authenticateAccount(ctx context.Context, cfg savedConfig, opts accountAuthOpts) (session, string, error) {
	email := normalizeEmail(opts.email)
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
	if email == "" {
		if opts.missingCredsErr != "" {
			return session{}, "", errors.New(opts.missingCredsErr)
		}
		return session{}, "", errors.New("MEGA account email is required")
	}

	password := opts.password
	passwordFromConfig := false
	if password == "" && opts.allowSavedPassword && cfg.Account.Password != "" && strings.EqualFold(email, cfg.Account.Email) {
		password = cfg.Account.Password
		passwordFromConfig = true
	}
	if password == "" {
		entered, err := promptSecret(ctx, "MEGA account password: ")
		if err != nil {
			return session{}, "", err
		}
		password = entered
	}
	if password == "" {
		if opts.missingCredsErr != "" {
			return session{}, "", errors.New(opts.missingCredsErr)
		}
		return session{}, "", errors.New("MEGA account password is required")
	}

	fmt.Printf("Logging in to MEGA account %s...\n", email)
	sess, err := loginMegaAccount(ctx, email, password, opts.mfa)
	if err != nil {
		return session{}, "", err
	}
	if opts.persist {
		passwordToStore := passwordToPersist(cfg, email, password, opts.savePassword, passwordFromConfig)
		if err := saveAccountSessionWithConfig(cfg, email, passwordToStore, sess); err != nil {
			return session{}, "", err
		}
	}
	return sess, email, nil
}

func resolveUploadSession(ctx context.Context, useAccount bool, accountEmail, accountPassword, mfa string, savePassword bool) (session, string, error) {
	if !useAccount {
		fmt.Println("Creating anonymous MEGA/transfer.it session...")
		sess, err := createAnonymousSession(ctx)
		return sess, "anonymous MEGA/transfer.it session", err
	}

	cfg, _, err := loadSavedConfig()
	if err != nil {
		return session{}, "", err
	}

	email := normalizeEmail(accountEmail)
	if email == "" {
		email = normalizeEmail(cfg.Account.Email)
	}
	if accountPassword == "" && cfg.Account.SID != "" && (email == "" || strings.EqualFold(email, cfg.Account.Email)) {
		label := "saved MEGA account session"
		if cfg.Account.Email != "" {
			label += " for " + cfg.Account.Email
		}
		return session{sid: cfg.Account.SID}, label, nil
	}

	sess, loggedEmail, err := authenticateAccount(ctx, cfg, accountAuthOpts{
		email:              accountEmail,
		password:           accountPassword,
		mfa:                mfa,
		savePassword:       savePassword,
		allowSavedPassword: true,
		persist:            true,
	})
	if err != nil {
		return session{}, "", err
	}
	return sess, "MEGA account session for " + loggedEmail, nil
}

func refreshAccountSession(ctx context.Context, accountEmail, accountPassword, mfa string, savePassword bool) (session, string, error) {
	cfg, _, err := loadSavedConfig()
	if err != nil {
		return session{}, "", err
	}
	sess, email, err := authenticateAccount(ctx, cfg, accountAuthOpts{
		email:              accountEmail,
		password:           accountPassword,
		mfa:                mfa,
		savePassword:       savePassword,
		allowSavedPassword: true,
		persist:            true,
		missingCredsErr:    "MEGA account email and password are required to refresh the account session",
	})
	if err != nil {
		return session{}, "", err
	}
	return sess, "refreshed MEGA account session for " + email, nil
}

func createAnonymousSession(ctx context.Context) (session, error) {
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
	if err := (&apiClient{base: megaAPI}).callOnce(ctx, upReq, nil, &upRes); err != nil {
		return session{}, err
	}
	if len(upRes) != 1 {
		return session{}, errors.New("unexpected up response")
	}

	var usRes []struct {
		TSID string `json:"tsid"`
		Key  string `json:"k"`
	}
	if err := (&apiClient{base: megaAPI}).call(ctx, []map[string]any{{"a": "us", "user": upRes[0]}}, nil, &usRes); err != nil {
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

func loginMegaAccount(ctx context.Context, email, password, mfa string) (session, error) {
	email = normalizeEmail(email)
	if email == "" {
		return session{}, errors.New("MEGA account email is required")
	}
	if password == "" {
		return session{}, errors.New("MEGA account password is required")
	}

	method, err := getMegaLoginMethod(ctx, email)
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
	return completeMegaLogin(ctx, email, userHash, passwordKey, mfa)
}

func getMegaLoginMethod(ctx context.Context, email string) (megaLoginMethod, error) {
	var raw []json.RawMessage
	err := (&apiClient{base: megaAPI}).call(ctx, []map[string]any{{"a": "us0", "user": email}}, nil, &raw)
	if err != nil {
		return megaLoginMethod{}, err
	}
	if len(raw) != 1 {
		return megaLoginMethod{}, errors.New("unexpected us0 response")
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

func completeMegaLogin(ctx context.Context, email, userHash string, passwordKey []uint32, mfa string) (session, error) {
	req := map[string]any{"a": "us", "user": email, "uh": userHash}
	if mfa != "" {
		req["mfa"] = mfa
	}
	var raw []json.RawMessage
	err := (&apiClient{base: megaAPI}).call(ctx, []map[string]any{req}, nil, &raw)
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
	return saveAccountSessionWithConfig(cfg, email, passwordToStore, sess)
}

func saveAccountSessionWithConfig(cfg savedConfig, email, passwordToStore string, sess session) error {
	cfg.Account = savedAccount{
		Email:     normalizeEmail(email),
		Password:  passwordToStore,
		SID:       sess.sid,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return saveSavedConfig(cfg)
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
