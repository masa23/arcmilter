package arcmilter

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/mail"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/masa23/arcmilter/config"
	"github.com/masa23/mmauth/dkim2"
)

const (
	dkim2ContextMetadataLimit = 64 << 10
	dkim2StoreStateLimit      = 64 << 10
	dkim2StoreStateVersion    = 4
	dkim2StoreQuotaKeyLimit   = config.MaxDKIM2ForwardRecipients
	dkim2StoreQuotaBytesLimit = config.MaxDKIM2ForwardRecipientQuotaBytes
)

var (
	errDKIM2CacheMiss       = errors.New("DKIM2 forwarding context not found")
	errDKIM2CacheExpired    = errors.New("DKIM2 forwarding context expired")
	errDKIM2CacheCapacity   = errors.New("DKIM2 context store capacity exceeded")
	errDKIM2ContextMetadata = errors.New("invalid DKIM2 context metadata")
	errDKIM2FileUnlinked    = errors.New("DKIM2 store file was unlinked after opening")
)

// 使用量は全プロセスが同じ Flock の下で更新する。操作前の Dirty を永続化し、
// 中断された書込・削除や壊れた管理情報は次の操作で一度だけ再計算する。
type dkim2StoreState struct {
	Version        int                       `json:"version"`
	Dirty          bool                      `json:"dirty"`
	StoredBytes    int64                     `json:"stored_bytes"`
	ScannedAt      int64                     `json:"scanned_at"`
	NextExpiry     int64                     `json:"next_expiry"`
	MaxAgeSeconds  int64                     `json:"max_age_seconds"`
	DirectoryTime  int64                     `json:"directory_time"`
	QuotaPolicy    string                    `json:"quota_policy,omitempty"`
	RecipientBytes map[string]int64          `json:"recipient_bytes,omitempty"`
	FIFO           dkim2FIFOState            `json:"fifo"`
	RecipientFIFO  map[string]dkim2FIFOState `json:"recipient_fifo,omitempty"`
	Checksum       string                    `json:"checksum"`
}

// Raw は JSON に含めず、メタデータ行の直後に元のバイト列で保存する。
type dkim2ForwardContext struct {
	Envelope       dkim2.Envelope
	SigningDomains []string
	Raw            []byte
}

type dkim2ContextMetadata struct {
	Version        int            `json:"version"`
	Created        int64          `json:"created"`
	Order          int64          `json:"order,omitempty"`
	Envelope       dkim2.Envelope `json:"envelope"`
	SigningDomains []string       `json:"signing_domains"`
	RawBytes       int64          `json:"raw_bytes"`
	SHA256         string         `json:"sha256"`
}

func dkim2StoreOptions(options config.DKIM2ForwardingConfig) (config.DKIM2ForwardingConfig, error) {
	if !filepath.IsAbs(options.StoreDirectory) {
		return options, errors.New("DKIM2 context store must be an absolute path")
	}
	if options.MaxAgeSeconds == 0 {
		options.MaxAgeSeconds = config.DefaultDKIM2ForwardingMaxAgeSeconds
	}
	if options.MaxStoredBytes == 0 {
		options.MaxStoredBytes = config.DefaultDKIM2ForwardingMaxStoredBytes
	}
	if len(options.ForwardRecipients) > 0 && options.MaxStoredBytesPerRecipient == 0 {
		options.MaxStoredBytesPerRecipient = min(config.DefaultDKIM2ForwardingMaxStoredBytesPerRecipient, options.MaxStoredBytes)
		if len(options.ForwardRecipients) > 1 {
			options.MaxStoredBytesPerRecipient = min(options.MaxStoredBytesPerRecipient,
				max(int64(1), options.MaxStoredBytes/int64(len(options.ForwardRecipients))))
		}
	}
	if options.MaxAgeSeconds < 1 || options.MaxAgeSeconds > config.MaxDKIM2ForwardingMaxAgeSeconds || options.MaxStoredBytes < 1 {
		return options, errors.New("invalid DKIM2 context store limits")
	}
	if options.MaxStoredBytesPerRecipient < 0 || options.MaxStoredBytesPerRecipient > options.MaxStoredBytes {
		return options, errors.New("invalid DKIM2 recipient context store limit")
	}
	if _, _, err := dkim2StoreQuotaPolicy(options); err != nil {
		return options, err
	}
	return options, nil
}

// dkim2StoreQuotaPolicy returns stable configured quota keys and a fingerprint
// persisted in .state. Reordering equivalent configuration does not force a
// rebuild, while a rule or limit change always does.
func dkim2StoreQuotaPolicy(options config.DKIM2ForwardingConfig) ([]string, string, error) {
	if len(options.ForwardRecipients) == 0 || options.MaxStoredBytesPerRecipient == 0 {
		return nil, "", nil
	}
	if len(options.ForwardRecipients) > dkim2StoreQuotaKeyLimit {
		return nil, "", errors.New("too many DKIM2 forwarding recipient quota keys")
	}
	seen := make(map[string]bool, len(options.ForwardRecipients))
	keys := make([]string, 0, len(options.ForwardRecipients))
	total := 0
	for _, recipient := range options.ForwardRecipients {
		local, domain, err := canonicalDKIM2ForwardRecipient(recipient)
		if err != nil {
			return nil, "", fmt.Errorf("invalid DKIM2 forwarding recipient quota key: %w", err)
		}
		key := local + "@" + domain
		if seen[key] {
			continue
		}
		total += len(key)
		if total > dkim2StoreQuotaBytesLimit {
			return nil, "", errors.New("DKIM2 forwarding recipient quota keys are too large")
		}
		seen[key] = true
		keys = append(keys, key)
	}
	sort.Strings(keys)
	encoded, _ := json.Marshal(struct {
		Limit int64    `json:"limit"`
		Keys  []string `json:"keys"`
	}{options.MaxStoredBytesPerRecipient, keys})
	sum := sha256.Sum256(encoded)
	return keys, hex.EncodeToString(sum[:]), nil
}

// Persist only a fixed-size identifier for a configured recipient rule. Raw
// SMTPUTF8 local-parts can expand when JSON escaped and must not make the
// bounded accounting state unwritable.
func dkim2StoreQuotaKey(rule string) string {
	sum := sha256.Sum256([]byte(rule))
	return hex.EncodeToString(sum[:])
}

func dkim2StoreQuotaKeys(options config.DKIM2ForwardingConfig, envelope dkim2.Envelope) ([]string, error) {
	rules, _, err := dkim2StoreQuotaPolicy(options)
	if err != nil || len(rules) == 0 {
		return nil, err
	}
	matched := make(map[string]bool, len(rules))
	for _, recipient := range envelope.RcptTo {
		local, domain, err := canonicalDKIM2ForwardRecipient(recipient)
		if err != nil {
			continue
		}
		for _, rule := range rules {
			ruleLocal, ruleDomain, _ := canonicalDKIM2ForwardRecipient(rule)
			if domain == ruleDomain && (ruleLocal == "*" || local == ruleLocal) {
				matched[dkim2StoreQuotaKey(rule)] = true
			}
		}
	}
	keys := make([]string, 0, len(matched))
	for key := range matched {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

func dkim2StoreQuotaExceeded(state dkim2StoreState, options config.DKIM2ForwardingConfig, keys []string, needed int64) bool {
	if options.MaxStoredBytesPerRecipient == 0 {
		return false
	}
	for _, key := range keys {
		used := state.RecipientBytes[key]
		if used > options.MaxStoredBytesPerRecipient || needed > options.MaxStoredBytesPerRecipient-used {
			return true
		}
	}
	return false
}

func addDKIM2StoreQuota(state *dkim2StoreState, keys []string, size int64) error {
	if len(keys) == 0 {
		return nil
	}
	if state.RecipientBytes == nil {
		state.RecipientBytes = make(map[string]int64, len(keys))
	}
	for _, key := range keys {
		used := state.RecipientBytes[key]
		if size > 0 && used > math.MaxInt64-size {
			return errors.New("DKIM2 recipient context store size overflow")
		}
		used += size
		if used < 0 {
			return errors.New("DKIM2 recipient context store size underflow")
		}
		if used == 0 {
			delete(state.RecipientBytes, key)
		} else {
			state.RecipientBytes[key] = used
		}
	}
	return nil
}

func checkDKIM2StoreDirectory(path string, create bool) error {
	if create {
		if err := os.MkdirAll(path, 0700); err != nil {
			return err
		}
	}
	if err := checkDKIM2StoreParents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 || !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("DKIM2 context store must be a private directory owned by the service user (0700)")
	}
	return nil
}

// A private leaf is insufficient when another user can replace an ancestor
// after validation. A root- or service-owned sticky directory (for example,
// /tmp) protects an owned child from other writers.
func checkDKIM2StoreParents(path string) error {
	check := func(parent string) error {
		current := string(os.PathSeparator)
		for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(parent), current), current) {
			if component != "" {
				current = filepath.Join(current, component)
			}
			info, err := os.Lstat(current)
			if err != nil {
				return err
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
				return errors.New("DKIM2 context store has an untrusted parent directory")
			}
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if !info.IsDir() || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
				return errors.New("DKIM2 context store has an untrusted parent directory")
			}
		}
		return nil
	}
	parent := filepath.Dir(path)
	if err := check(parent); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return err
	}
	return check(resolved)
}

func validDKIM2ContextID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func openDKIM2ContextFile(path string, flags int) (*os.File, error) {
	// NONBLOCK は誤って置かれた FIFO 等による待ち続けを防ぐ。
	// O_TRUNC must follow the ownership/link checks: opening a hard link with
	// O_TRUNC would damage its other name before Stat could reject it.
	truncate := flags&os.O_TRUNC != 0
	file, err := os.OpenFile(path, flags&^os.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	if err := validateOpenedDKIM2ContextFile(file, truncate); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateOpenedDKIM2ContextFile(file *os.File, truncate bool) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !ok ||
		stat.Uid != uint32(os.Geteuid()) {
		return errors.New("DKIM2 context file must be a private regular file owned by the service user without hard links (0600)")
	}
	// Eviction can unlink a file between OpenFile and Stat. A missing inode
	// name is distinct from an unsafe inode with multiple hard links.
	if stat.Nlink == 0 {
		return errDKIM2FileUnlinked
	}
	if stat.Nlink != 1 {
		return errors.New("DKIM2 context file must be a private regular file owned by the service user without hard links (0600)")
	}
	if truncate {
		if err := file.Truncate(0); err != nil {
			return err
		}
	}
	return nil
}

func readDKIM2ContextMetadata(reader *bufio.Reader) (dkim2ContextMetadata, int, error) {
	var metadata dkim2ContextMetadata
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		// 通常のメタデータは小さいバッファ内で処理し、長い行だけ上限まで拡張する。
		line = append([]byte(nil), line...)
		for errors.Is(err, bufio.ErrBufferFull) && len(line) <= dkim2ContextMetadataLimit {
			var part []byte
			part, err = reader.ReadSlice('\n')
			line = append(line, part...)
		}
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return metadata, 0, fmt.Errorf("read DKIM2 context metadata: %w", err)
	}
	if err != nil || len(line) > dkim2ContextMetadataLimit {
		return metadata, 0, fmt.Errorf("%w: incomplete or oversized metadata", errDKIM2ContextMetadata)
	}
	// encoding/json replaces malformed UTF-8 inside strings. A damaged SMTP
	// address must not silently become a different quota or signing identity.
	if !utf8.Valid(line) {
		return metadata, 0, fmt.Errorf("%w: invalid UTF-8", errDKIM2ContextMetadata)
	}
	if err := json.Unmarshal(line, &metadata); err != nil {
		return metadata, 0, fmt.Errorf("%w: %w", errDKIM2ContextMetadata, err)
	}
	return metadata, len(line), nil
}

func validDKIM2ContextMetadata(metadata dkim2ContextMetadata, now int64) bool {
	return metadata.Version == 1 && metadata.Created > 0 && metadata.Created <= now+60 && metadata.Order >= 0 &&
		metadata.RawBytes > 0 && metadata.RawBytes <= config.DefaultDKIM2MaxMessageBytes &&
		validDKIM2StoredEnvelope(metadata.Envelope) && validDKIM2SigningDomains(metadata.SigningDomains) &&
		validDKIM2ContextID(metadata.SHA256)
}

func validDKIM2StoredEnvelope(envelope dkim2.Envelope) bool {
	validPath := func(path string, null bool) bool {
		if path == "<>" {
			return null
		}
		if len(path) < 3 || path[0] != '<' || path[len(path)-1] != '>' || !utf8.ValidString(path) || strings.ContainsAny(path, "\r\n\x00") {
			return false
		}
		for i := range path {
			if path[i] < 32 || path[i] == 127 {
				return false
			}
		}
		inner := path[1 : len(path)-1]
		if !null && len(inner) == len("Postmaster") && strings.EqualFold(inner, "Postmaster") {
			return true
		}
		if strings.HasPrefix(inner, "@") {
			route, mailbox, ok := strings.Cut(inner, ":")
			if !ok {
				return false
			}
			for _, domain := range strings.Split(route, ",") {
				if len(domain) < 2 || domain[0] != '@' {
					return false
				}
				if _, err := normalizeDKIM2Domain(domain[1:]); err != nil {
					return false
				}
			}
			inner = mailbox
		}
		if _, err := dkim2Mailbox(inner); err != nil {
			return false
		}
		at := strings.LastIndexByte(inner, '@')
		if at <= 0 {
			return false
		}
		domain := inner[at+1:]
		if strings.HasPrefix(domain, "[") && (len(domain) < 3 || !strings.HasSuffix(domain, "]")) {
			return false
		}
		// net/mail's domain-literal grammar is narrower than SMTP's (for
		// example, it rejects the IPv6: prefix and registered literal tags).
		// Validate only the local-part with it; dkim2Mailbox validates the
		// actual DNS domain without narrowing SMTP address-literal support.
		local := inner[:at]
		address, err := mail.ParseAddress("<" + local + "@example.invalid>")
		if err != nil {
			return false
		}
		if local[0] == '"' {
			return len(local) >= 2 && local[len(local)-1] == '"'
		}
		// SMTP paths do not permit the comments or surrounding whitespace
		// that net/mail may otherwise discard from an unquoted local-part.
		return address.Address == local+"@example.invalid"
	}
	if !validPath(envelope.MailFrom, true) || len(envelope.RcptTo) == 0 {
		return false
	}
	for _, recipient := range envelope.RcptTo {
		if !validPath(recipient, false) {
			return false
		}
	}
	return true
}

func validDKIM2SigningDomains(domains []string) bool {
	if len(domains) == 0 {
		return false
	}
	for _, domain := range domains {
		if domain == "" || strings.ContainsAny(domain, "<> \t\r\n\x00") {
			return false
		}
		if _, err := normalizeDKIM2Domain(domain); err != nil {
			return false
		}
	}
	return true
}

func lockDKIM2Store(options config.DKIM2ForwardingConfig, create bool) (*os.File, error) {
	if err := checkDKIM2StoreDirectory(options.StoreDirectory, create); err != nil {
		return nil, err
	}
	lock, err := openDKIM2ContextFile(filepath.Join(options.StoreDirectory, ".lock"), os.O_RDWR|os.O_CREATE)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func unlockDKIM2Store(lock *os.File) {
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = lock.Close()
}

func syncDKIM2StoreDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func dkim2StoreStateChecksum(state dkim2StoreState) string {
	state.Checksum = ""
	data, _ := json.Marshal(state)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validDKIM2StoreQuotaState(state dkim2StoreState) bool {
	if !validDKIM2FIFOState(state.FIFO) || len(state.RecipientFIFO) > dkim2StoreQuotaKeyLimit {
		return false
	}
	for key, queue := range state.RecipientFIFO {
		if !validDKIM2ContextID(key) || !validDKIM2FIFOState(queue) {
			return false
		}
	}
	if state.QuotaPolicy != "" && !validDKIM2ContextID(state.QuotaPolicy) {
		return false
	}
	if len(state.RecipientBytes) > dkim2StoreQuotaKeyLimit {
		return false
	}
	total := 0
	for key, used := range state.RecipientBytes {
		if !validDKIM2ContextID(key) || used <= 0 {
			return false
		}
		total += len(key)
		if total > dkim2StoreQuotaBytesLimit {
			return false
		}
	}
	return len(state.RecipientBytes) == 0 || state.QuotaPolicy != ""
}

// .state は固定 inode のまま更新する。ディレクトリの変更時刻には管理ファイルの
// 書換えを混ぜず、外部で ctx が削除・追加された場合も次回の保存で再計算できる。
func writeDKIM2StoreState(options config.DKIM2ForwardingConfig, state dkim2StoreState) error {
	if !validDKIM2StoreQuotaState(state) {
		return errors.New("invalid DKIM2 recipient quota state")
	}
	file, err := openDKIM2ContextFile(filepath.Join(options.StoreDirectory, ".state"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := os.Stat(options.StoreDirectory)
	if err != nil {
		return err
	}
	state.Version = dkim2StoreStateVersion
	state.DirectoryTime = info.ModTime().UnixNano()
	state.Checksum = dkim2StoreStateChecksum(state)
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(data) > dkim2StoreStateLimit {
		return errors.New("DKIM2 context store state exceeds 64 KiB")
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func readDKIM2StoreState(options config.DKIM2ForwardingConfig) (dkim2StoreState, bool, error) {
	var state dkim2StoreState
	file, err := openDKIM2ContextFile(filepath.Join(options.StoreDirectory, ".state"), os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return state, false, nil
	}
	if err != nil {
		return state, false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, dkim2StoreStateLimit+1))
	if err != nil {
		return state, false, err
	}
	if len(data) > dkim2StoreStateLimit || json.Unmarshal(data, &state) != nil ||
		state.Version != dkim2StoreStateVersion || state.StoredBytes < 0 || !validDKIM2StoreQuotaState(state) ||
		state.Checksum != dkim2StoreStateChecksum(state) {
		return state, false, nil
	}
	return state, true, nil
}

// LOCK_EX を保持した状態で呼ぶ。通常は小さい管理情報と索引のサイズだけを確認し、
// 期限切れはFIFOの先頭から回収する。全ファイルの走査は中断・破損・設定変更からの
// 復旧時だけに限り、容量回収ごとのO(n)走査を避ける。
func prepareDKIM2StoreState(options config.DKIM2ForwardingConfig, now int64) (dkim2StoreState, error) {
	state, valid, err := readDKIM2StoreState(options)
	if err != nil {
		return state, err
	}
	if !valid {
		state = dkim2StoreState{}
	}
	info, err := os.Stat(options.StoreDirectory)
	if err != nil {
		return state, err
	}
	_, quotaPolicy, err := dkim2StoreQuotaPolicy(options)
	if err != nil {
		return state, err
	}
	rebuild := !valid || state.Dirty || state.MaxAgeSeconds != options.MaxAgeSeconds ||
		state.DirectoryTime != info.ModTime().UnixNano() || state.ScannedAt > now || state.QuotaPolicy != quotaPolicy
	if !rebuild {
		indexesValid, indexErr := validDKIM2FIFOFiles(options, state)
		if indexErr != nil {
			return state, indexErr
		}
		rebuild = !indexesValid
	}
	if !rebuild && !(state.NextExpiry > 0 && state.NextExpiry <= now) {
		return state, nil
	}
	state.Dirty = true
	if err := writeDKIM2StoreState(options, state); err != nil {
		return state, err
	}
	if rebuild {
		state, err = cleanupDKIM2ForwardContexts(options, now)
	} else {
		err = expireDKIM2FIFO(options, &state, now)
		if errors.Is(err, errDKIM2FIFOInvalid) {
			state, err = cleanupDKIM2ForwardContexts(options, now)
		}
	}
	if err != nil {
		return state, err
	}
	if err := compactDKIM2FIFOs(options, &state); err != nil {
		return state, err
	}
	if err := syncDKIM2StoreDirectory(options.StoreDirectory); err != nil {
		return state, err
	}
	state.Dirty = false
	return state, writeDKIM2StoreState(options, state)
}

// 呼出し側は、この原文と実受信エンベロープで DKIM2 検証を完了させてから保存する。
func saveDKIM2ForwardContext(options config.DKIM2ForwardingConfig, envelope dkim2.Envelope, signingDomains []string, raw []byte) (string, error) {
	options, err := dkim2StoreOptions(options)
	if err != nil {
		return "", err
	}
	if int64(len(raw)) > config.DefaultDKIM2MaxMessageBytes {
		return "", errDKIM2CacheCapacity
	}
	if len(raw) == 0 ||
		!validDKIM2StoredEnvelope(envelope) || !validDKIM2SigningDomains(signingDomains) {
		return "", errors.New("invalid DKIM2 forwarding context")
	}
	quotaKeys, err := dkim2StoreQuotaKeys(options, envelope)
	if err != nil {
		return "", err
	}
	if len(options.ForwardRecipients) > 0 && options.MaxStoredBytesPerRecipient > 0 && len(quotaKeys) == 0 {
		return "", errors.New("DKIM2 forwarding context does not match a configured forwarding recipient")
	}
	lock, err := lockDKIM2Store(options, true)
	if err != nil {
		return "", err
	}
	defer unlockDKIM2Store(lock)

	now := time.Now().Unix()
	sum := sha256.Sum256(raw)
	metadata := dkim2ContextMetadata{Version: 1, Created: now, Order: time.Now().UnixNano(), Envelope: envelope,
		SigningDomains: signingDomains, RawBytes: int64(len(raw)), SHA256: hex.EncodeToString(sum[:])}
	line, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	line = append(line, '\n')
	if len(line) > dkim2ContextMetadataLimit {
		return "", errors.New("DKIM2 context metadata exceeds 64 KiB")
	}
	needed := int64(len(line)) + int64(len(raw))
	// Never evict accepted contexts for a new context that cannot fit alone.
	if needed > options.MaxStoredBytes {
		return "", errDKIM2CacheCapacity
	}
	if len(quotaKeys) > 0 && options.MaxStoredBytesPerRecipient > 0 && needed > options.MaxStoredBytesPerRecipient {
		return "", fmt.Errorf("%w: recipient context store capacity exceeded", errDKIM2CacheCapacity)
	}
	state, err := prepareDKIM2StoreState(options, now)
	if err != nil {
		return "", err
	}
	if options.CacheFailureAction == "tempfail" {
		if state.StoredBytes > options.MaxStoredBytes || needed > options.MaxStoredBytes-state.StoredBytes {
			return "", errDKIM2CacheCapacity
		}
		if dkim2StoreQuotaExceeded(state, options, quotaKeys, needed) {
			return "", fmt.Errorf("%w: recipient context store capacity exceeded", errDKIM2CacheCapacity)
		}
	}
	state.Dirty = true
	if err := writeDKIM2StoreState(options, state); err != nil {
		return "", err
	}
	if options.CacheFailureAction != "tempfail" {
		err := reclaimDKIM2FIFO(options, &state, needed, quotaKeys, now)
		if errors.Is(err, errDKIM2FIFOInvalid) {
			state, err = cleanupDKIM2ForwardContexts(options, now)
			if err == nil {
				err = reclaimDKIM2FIFO(options, &state, needed, quotaKeys, now)
			}
		}
		if err != nil {
			return "", err
		}
	}
	file, err := os.CreateTemp(options.StoreDirectory, ".tmp-")
	if err != nil {
		return "", err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	defer file.Close()
	if _, err := file.Write(line); err != nil {
		return "", err
	}
	if _, err := file.Write(raw); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	var token [32]byte
	for {
		if _, err := rand.Read(token[:]); err != nil {
			return "", err
		}
		id := hex.EncodeToString(token[:])
		final := filepath.Join(options.StoreDirectory, id+".ctx")
		if _, err := os.Lstat(final); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if err := os.Rename(temporary, final); err != nil {
			return "", err
		}
		if err := syncDKIM2StoreDirectory(options.StoreDirectory); err != nil {
			_ = os.Remove(final)
			return "", err
		}
		state.StoredBytes += needed
		if err := addDKIM2StoreQuota(&state, quotaKeys, needed); err != nil {
			_ = os.Remove(final)
			return "", err
		}
		if err := appendDKIM2FIFOContext(options, &state, dkim2FIFORecord{ID: id, Created: now, Order: metadata.Order, Size: needed, QuotaKeys: quotaKeys}); err != nil {
			_ = os.Remove(final)
			return "", err
		}
		if err := compactDKIM2FIFOs(options, &state); err != nil {
			_ = os.Remove(final)
			return "", err
		}
		if err := syncDKIM2StoreDirectory(options.StoreDirectory); err != nil {
			_ = os.Remove(final)
			return "", err
		}
		expires := now + options.MaxAgeSeconds
		if state.NextExpiry == 0 || expires < state.NextExpiry {
			state.NextExpiry = expires
		}
		state.Dirty = false
		if err := writeDKIM2StoreState(options, state); err != nil {
			_ = os.Remove(final)
			return "", err
		}
		return id, nil
	}
}

// LOCK_EX を保持した状態で呼ぶ。原文は再送・複数配送に備えて期限まで残す。
func cleanupDKIM2ForwardContexts(options config.DKIM2ForwardingConfig, now int64) (dkim2StoreState, error) {
	_, quotaPolicy, err := dkim2StoreQuotaPolicy(options)
	if err != nil {
		return dkim2StoreState{}, err
	}
	state := dkim2StoreState{Version: dkim2StoreStateVersion, ScannedAt: now, MaxAgeSeconds: options.MaxAgeSeconds, QuotaPolicy: quotaPolicy}
	entries, err := os.ReadDir(options.StoreDirectory)
	if err != nil {
		return state, err
	}
	reader := bufio.NewReaderSize(nil, 1024)
	var records []dkim2FIFORecord
	for _, entry := range entries {
		name := entry.Name()
		if name == ".lock" || name == ".state" {
			continue
		}
		path := filepath.Join(options.StoreDirectory, name)
		if dkim2FIFOName(name) {
			file, err := openDKIM2ContextFile(path, os.O_RDONLY)
			if err != nil {
				return state, err
			}
			_ = file.Close()
			continue
		}
		if strings.HasPrefix(name, ".tmp-") && entry.Type().IsRegular() {
			// このロックを持つ書込処理以外の一時ファイルはクラッシュの残骸。
			if err := os.Remove(path); err != nil {
				return state, err
			}
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return state, err
		}
		if !info.Mode().IsRegular() {
			return state, errors.New("unexpected nonregular file in DKIM2 context store")
		}
		var quotaKeys []string
		var record *dkim2FIFORecord
		if strings.HasSuffix(name, ".ctx") && validDKIM2ContextID(strings.TrimSuffix(name, ".ctx")) {
			file, err := openDKIM2ContextFile(path, os.O_RDONLY)
			if err != nil {
				return state, err
			}
			reader.Reset(file)
			metadata, metadataBytes, metadataErr := readDKIM2ContextMetadata(reader)
			_ = file.Close()
			if metadataErr != nil && !errors.Is(metadataErr, errDKIM2ContextMetadata) {
				// A temporary read failure must not turn an unreadable envelope
				// into a clean accounting entry with zero recipient usage.
				return state, metadataErr
			}
			if metadataErr == nil && (!validDKIM2ContextMetadata(metadata, now) || info.Size() != int64(metadataBytes)+metadata.RawBytes) {
				metadataErr = errDKIM2ContextMetadata
			}
			if metadataErr != nil {
				// Corrupt metadata cannot be assigned to a recipient quota.
				// Retain it fail-closed until its mtime-based retention expires;
				// only then can it be removed without publishing undercounted state.
				if info.ModTime().Unix() > now-options.MaxAgeSeconds {
					return state, metadataErr
				}
				if err := os.Remove(path); err != nil {
					return state, err
				}
				continue
			}
			expires := metadata.Created + options.MaxAgeSeconds
			if expires <= now {
				if err := os.Remove(path); err != nil {
					return state, err
				}
				continue
			}
			if state.NextExpiry == 0 || expires < state.NextExpiry {
				state.NextExpiry = expires
			}
			quotaKeys, err = dkim2StoreQuotaKeys(options, metadata.Envelope)
			if err != nil {
				return state, err
			}
			record = &dkim2FIFORecord{ID: strings.TrimSuffix(name, ".ctx"), Created: metadata.Created, Order: metadata.Order, Size: info.Size(), QuotaKeys: quotaKeys}
		}
		if info.Size() > math.MaxInt64-state.StoredBytes {
			return state, errors.New("DKIM2 context store size overflow")
		}
		state.StoredBytes += info.Size()
		if err := addDKIM2StoreQuota(&state, quotaKeys, info.Size()); err != nil {
			return state, err
		}
		if record != nil {
			records = append(records, *record)
		}
	}
	err = rebuildDKIM2FIFOs(options, &state, records)
	return state, err
}

// この保存試行が公開できなかったコンテキストだけを取り消す。正常に受信済みの
// コンテキストは、再送・複数配送が再読込できるよう通常の TTL まで保持する。
func removeDKIM2ForwardContext(options config.DKIM2ForwardingConfig, id string) error {
	if !validDKIM2ContextID(id) {
		return errors.New("invalid DKIM2 context ID")
	}
	options, err := dkim2StoreOptions(options)
	if err != nil {
		return err
	}
	lock, err := lockDKIM2Store(options, false)
	if err != nil {
		return err
	}
	defer unlockDKIM2Store(lock)
	state, err := prepareDKIM2StoreState(options, time.Now().Unix())
	if err != nil {
		return err
	}
	path := filepath.Join(options.StoreDirectory, id+".ctx")
	file, err := openDKIM2ContextFile(path, os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	reader := bufio.NewReaderSize(file, dkim2ContextMetadataLimit+1)
	metadata, _, metadataErr := readDKIM2ContextMetadata(reader)
	info, err := file.Stat()
	_ = file.Close()
	if err != nil {
		return err
	}
	last, lastErr := lastDKIM2FIFORecord(options, state)
	state.Dirty = true
	if err := writeDKIM2StoreState(options, state); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if err := syncDKIM2StoreDirectory(options.StoreDirectory); err != nil {
		return err
	}
	var quotaKeys []string
	if metadataErr == nil {
		quotaKeys, err = dkim2StoreQuotaKeys(options, metadata.Envelope)
	}
	fastPath := lastErr == nil && last.ID == id && metadataErr == nil && err == nil &&
		validDKIM2ContextMetadata(metadata, time.Now().Unix()) && info.Size() == last.Size &&
		metadata.Created == last.Created && metadata.Order == last.Order &&
		dkim2FIFOQuotaHash(quotaKeys) == last.QuotaHash && state.StoredBytes >= info.Size()
	if fastPath {
		state.StoredBytes -= info.Size()
		if err := addDKIM2StoreQuota(&state, quotaKeys, -info.Size()); err != nil {
			fastPath = false
		} else if err := decrementDKIM2FIFO(&state, quotaKeys); err != nil {
			fastPath = false
		}
	}
	if !fastPath {
		// The final FIFO record belongs to this attempted save in the common
		// case. If another save interleaved, or metadata changed, rebuild after
		// deletion instead of trusting possibly wrong recipient accounting.
		state, err = cleanupDKIM2ForwardContexts(options, time.Now().Unix())
		if err != nil {
			return err
		}
	}
	if err := compactDKIM2FIFOs(options, &state); err != nil {
		return err
	}
	if err := syncDKIM2StoreDirectory(options.StoreDirectory); err != nil {
		return err
	}
	state.Dirty = false
	return writeDKIM2StoreState(options, state)
}

func dkim2ContextOpenError(err error) error {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, errDKIM2FileUnlinked) {
		return fmt.Errorf("%w: %w", errDKIM2CacheMiss, err)
	}
	return err
}

func loadDKIM2ForwardContext(options config.DKIM2ForwardingConfig, id string) (*dkim2ForwardContext, error) {
	if !validDKIM2ContextID(id) {
		return nil, errors.New("invalid DKIM2 context ID")
	}
	options, err := dkim2StoreOptions(options)
	if err != nil {
		return nil, err
	}
	if err := checkDKIM2StoreDirectory(options.StoreDirectory, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %w", errDKIM2CacheMiss, err)
		}
		return nil, err
	}
	file, err := openDKIM2ContextFile(filepath.Join(options.StoreDirectory, id+".ctx"), os.O_RDONLY)
	if err != nil {
		return nil, dkim2ContextOpenError(err)
	}
	defer file.Close()
	reader := bufio.NewReaderSize(file, dkim2ContextMetadataLimit+1)
	metadata, metadataBytes, err := readDKIM2ContextMetadata(reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if !validDKIM2ContextMetadata(metadata, now) {
		return nil, errDKIM2ContextMetadata
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() != int64(metadataBytes)+metadata.RawBytes {
		return nil, errors.New("DKIM2 context length mismatch")
	}
	raw := make([]byte, metadata.RawBytes)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if metadata.SHA256 != hex.EncodeToString(sum[:]) {
		return nil, errors.New("DKIM2 context checksum mismatch")
	}
	if metadata.Created <= now-options.MaxAgeSeconds {
		return nil, errDKIM2CacheExpired
	}
	return &dkim2ForwardContext{Envelope: metadata.Envelope, SigningDomains: metadata.SigningDomains, Raw: raw}, nil
}

// The receiver's periodic GC uses a nonblocking lock so shutdown and live
// SMTP sessions are not delayed by a concurrent storage operation.
func cleanupExpiredDKIM2ForwardContexts(options config.DKIM2ForwardingConfig, now int64) error {
	options, err := dkim2StoreOptions(options)
	if err != nil {
		return err
	}
	if err := checkDKIM2StoreDirectory(options.StoreDirectory, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	lock, err := openDKIM2ContextFile(filepath.Join(options.StoreDirectory, ".lock"), os.O_RDWR|os.O_CREATE)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil
		}
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_, err = prepareDKIM2StoreState(options, now)
	return err
}
