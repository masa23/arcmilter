package arcmilter

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/masa23/arcmilter/config"
)

// Each FIFO is an append-only sequence of fixed-size, checksummed records.
// Cursors live in the bounded .state file. Quota FIFOs contain references to
// the same context, so quota eviction does not scan unrelated messages.
const dkim2FIFORecordBytes int64 = 120
const dkim2FIFOCompactBytes int64 = 64 << 10

type dkim2FIFOState struct {
	Head int64 `json:"head"`
	Tail int64 `json:"tail"`
	Live int64 `json:"live"`
}

type dkim2FIFORecord struct {
	ID        string
	Created   int64
	Order     int64
	Size      int64
	QuotaKeys []string
	QuotaHash [32]byte
}

var errDKIM2FIFOInvalid = errors.New("invalid DKIM2 FIFO index")

func validDKIM2FIFOState(queue dkim2FIFOState) bool {
	return queue.Head >= 0 && queue.Tail >= queue.Head && queue.Head%dkim2FIFORecordBytes == 0 &&
		queue.Tail%dkim2FIFORecordBytes == 0 && queue.Live >= 0 && queue.Live <= (queue.Tail-queue.Head)/dkim2FIFORecordBytes
}

func dkim2FIFOPath(options config.DKIM2ForwardingConfig, key string) string {
	name := ".fifo"
	if key != "" {
		name += "-" + key
	}
	return filepath.Join(options.StoreDirectory, name)
}

func dkim2FIFOName(name string) bool {
	return name == ".fifo" || strings.HasPrefix(name, ".fifo-") && validDKIM2ContextID(strings.TrimPrefix(name, ".fifo-"))
}

func getDKIM2FIFO(state *dkim2StoreState, key string) dkim2FIFOState {
	if key == "" {
		return state.FIFO
	}
	return state.RecipientFIFO[key]
}

func setDKIM2FIFO(state *dkim2StoreState, key string, queue dkim2FIFOState) {
	if key == "" {
		state.FIFO = queue
		return
	}
	if state.RecipientFIFO == nil {
		state.RecipientFIFO = make(map[string]dkim2FIFOState)
	}
	state.RecipientFIFO[key] = queue
}

func encodeDKIM2FIFORecord(record dkim2FIFORecord) []byte {
	data := make([]byte, dkim2FIFORecordBytes)
	id, _ := hex.DecodeString(record.ID)
	copy(data[:32], id)
	binary.BigEndian.PutUint64(data[32:40], uint64(record.Created))
	binary.BigEndian.PutUint64(data[40:48], uint64(record.Order))
	binary.BigEndian.PutUint64(data[48:56], uint64(record.Size))
	hash := dkim2FIFOQuotaHash(record.QuotaKeys)
	copy(data[56:88], hash[:])
	sum := sha256.Sum256(data[:88])
	copy(data[88:], sum[:])
	return data
}

func dkim2FIFOQuotaHash(keys []string) [32]byte {
	// Quota keys are sorted, fixed-size hex identifiers. A separator keeps the
	// encoding unambiguous even if that representation changes later.
	return sha256.Sum256([]byte(strings.Join(keys, "\n")))
}

func decodeDKIM2FIFORecord(data []byte) (dkim2FIFORecord, error) {
	if int64(len(data)) != dkim2FIFORecordBytes {
		return dkim2FIFORecord{}, errDKIM2FIFOInvalid
	}
	sum := sha256.Sum256(data[:88])
	if !bytes.Equal(sum[:], data[88:]) {
		return dkim2FIFORecord{}, errDKIM2FIFOInvalid
	}
	record := dkim2FIFORecord{ID: hex.EncodeToString(data[:32]), Created: int64(binary.BigEndian.Uint64(data[32:40])),
		Order: int64(binary.BigEndian.Uint64(data[40:48])), Size: int64(binary.BigEndian.Uint64(data[48:56]))}
	copy(record.QuotaHash[:], data[56:88])
	if record.Created <= 0 || record.Order < 0 || record.Size <= 0 {
		return dkim2FIFORecord{}, errDKIM2FIFOInvalid
	}
	return record, nil
}

func lastDKIM2FIFORecord(options config.DKIM2ForwardingConfig, state dkim2StoreState) (dkim2FIFORecord, error) {
	queue := state.FIFO
	if queue.Tail <= queue.Head {
		return dkim2FIFORecord{}, errDKIM2FIFOInvalid
	}
	file, err := openDKIM2ContextFile(dkim2FIFOPath(options, ""), os.O_RDONLY)
	if err != nil {
		return dkim2FIFORecord{}, err
	}
	defer file.Close()
	var data [dkim2FIFORecordBytes]byte
	if _, err := file.ReadAt(data[:], queue.Tail-dkim2FIFORecordBytes); err != nil {
		return dkim2FIFORecord{}, err
	}
	return decodeDKIM2FIFORecord(data[:])
}

func validDKIM2FIFOFiles(options config.DKIM2ForwardingConfig, state dkim2StoreState) (bool, error) {
	check := func(key string, queue dkim2FIFOState) (bool, error) {
		file, err := openDKIM2ContextFile(dkim2FIFOPath(options, key), os.O_RDONLY)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		defer file.Close()
		info, err := file.Stat()
		return err == nil && info.Size() == queue.Tail, err
	}
	if ok, err := check("", state.FIFO); !ok || err != nil {
		return ok, err
	}
	for key, queue := range state.RecipientFIFO {
		if ok, err := check(key, queue); !ok || err != nil {
			return ok, err
		}
	}
	return true, nil
}

func appendDKIM2FIFO(options config.DKIM2ForwardingConfig, state *dkim2StoreState, key string, record dkim2FIFORecord) error {
	queue := getDKIM2FIFO(state, key)
	file, err := openDKIM2ContextFile(dkim2FIFOPath(options, key), os.O_RDWR|os.O_CREATE)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteAt(encodeDKIM2FIFORecord(record), queue.Tail); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	queue.Tail += dkim2FIFORecordBytes
	queue.Live++
	setDKIM2FIFO(state, key, queue)
	return nil
}

func appendDKIM2FIFOContext(options config.DKIM2ForwardingConfig, state *dkim2StoreState, record dkim2FIFORecord) error {
	if err := appendDKIM2FIFO(options, state, "", record); err != nil {
		return err
	}
	for _, key := range record.QuotaKeys {
		if err := appendDKIM2FIFO(options, state, key, record); err != nil {
			return err
		}
	}
	return nil
}

// A missing context is a stale index entry left by rollback or quota eviction.
// Every other error, including a symlink, remains an error rather than a miss.
func peekDKIM2FIFO(options config.DKIM2ForwardingConfig, state *dkim2StoreState, key string, now int64) (*dkim2FIFORecord, error) {
	queue := getDKIM2FIFO(state, key)
	file, err := openDKIM2ContextFile(dkim2FIFOPath(options, key), os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var data [dkim2FIFORecordBytes]byte
	for queue.Head < queue.Tail {
		if _, err := file.ReadAt(data[:], queue.Head); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, fmt.Errorf("%w: %w", errDKIM2FIFOInvalid, err)
			}
			return nil, fmt.Errorf("read DKIM2 FIFO index: %w", err)
		}
		record, err := decodeDKIM2FIFORecord(data[:])
		if err != nil {
			return nil, err
		}
		context, err := openDKIM2ContextFile(filepath.Join(options.StoreDirectory, record.ID+".ctx"), os.O_RDONLY)
		if errors.Is(err, os.ErrNotExist) {
			queue.Head += dkim2FIFORecordBytes
			continue
		}
		if err != nil {
			return nil, err
		}
		metadata, metadataBytes, metadataErr := readDKIM2ContextMetadata(bufio.NewReaderSize(context, 1024))
		info, statErr := context.Stat()
		_ = context.Close()
		if statErr != nil {
			return nil, statErr
		}
		if metadataErr != nil {
			if errors.Is(metadataErr, errDKIM2ContextMetadata) {
				return nil, fmt.Errorf("%w: %w", errDKIM2FIFOInvalid, metadataErr)
			}
			return nil, metadataErr
		}
		if !validDKIM2ContextMetadata(metadata, now) || info.Size() != int64(metadataBytes)+metadata.RawBytes {
			return nil, fmt.Errorf("%w: %w", errDKIM2FIFOInvalid, errDKIM2ContextMetadata)
		}
		if info.Size() != record.Size || metadata.Created != record.Created || metadata.Order != record.Order {
			return nil, errDKIM2FIFOInvalid
		}
		keys, err := dkim2StoreQuotaKeys(options, metadata.Envelope)
		if err != nil {
			return nil, err
		}
		if dkim2FIFOQuotaHash(keys) != record.QuotaHash {
			return nil, errDKIM2FIFOInvalid
		}
		if key != "" {
			belongs := false
			for _, quotaKey := range keys {
				if quotaKey == key {
					belongs = true
					break
				}
			}
			if !belongs {
				return nil, errDKIM2FIFOInvalid
			}
		}
		setDKIM2FIFO(state, key, queue)
		return &record, nil
	}
	setDKIM2FIFO(state, key, queue)
	if queue.Live != 0 {
		return nil, errDKIM2FIFOInvalid
	}
	return nil, nil
}

func decrementDKIM2FIFO(state *dkim2StoreState, keys []string) error {
	for _, key := range append([]string{""}, keys...) {
		queue := getDKIM2FIFO(state, key)
		if queue.Live <= 0 {
			return errDKIM2FIFOInvalid
		}
		queue.Live--
		setDKIM2FIFO(state, key, queue)
	}
	return nil
}

func deleteDKIM2FIFOContext(options config.DKIM2ForwardingConfig, state *dkim2StoreState, record dkim2FIFORecord, now int64) error {
	path := filepath.Join(options.StoreDirectory, record.ID+".ctx")
	file, err := openDKIM2ContextFile(path, os.O_RDONLY)
	if err != nil {
		return err
	}
	metadata, metadataBytes, metadataErr := readDKIM2ContextMetadata(bufio.NewReaderSize(file, 1024))
	info, statErr := file.Stat()
	_ = file.Close()
	if metadataErr != nil {
		if errors.Is(metadataErr, errDKIM2ContextMetadata) {
			return fmt.Errorf("%w: %w", errDKIM2FIFOInvalid, metadataErr)
		}
		return metadataErr
	}
	if statErr != nil {
		return statErr
	}
	if !validDKIM2ContextMetadata(metadata, now) || info.Size() != int64(metadataBytes)+metadata.RawBytes {
		return fmt.Errorf("%w: %w", errDKIM2FIFOInvalid, errDKIM2ContextMetadata)
	}
	if info.Size() != record.Size || metadata.Created != record.Created || metadata.Order != record.Order {
		return errDKIM2FIFOInvalid
	}
	keys, err := dkim2StoreQuotaKeys(options, metadata.Envelope)
	if err != nil {
		return err
	}
	if dkim2FIFOQuotaHash(keys) != record.QuotaHash {
		return errDKIM2FIFOInvalid
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	state.StoredBytes -= record.Size
	if state.StoredBytes < 0 {
		return errDKIM2FIFOInvalid
	}
	if err := addDKIM2StoreQuota(state, keys, -record.Size); err != nil {
		return err
	}
	return decrementDKIM2FIFO(state, keys)
}

func expireDKIM2FIFO(options config.DKIM2ForwardingConfig, state *dkim2StoreState, now int64) error {
	for {
		record, err := peekDKIM2FIFO(options, state, "", now)
		if err != nil {
			return err
		}
		if record == nil {
			state.NextExpiry = 0
			return nil
		}
		state.NextExpiry = record.Created + options.MaxAgeSeconds
		if state.NextExpiry > now {
			return nil
		}
		if err := deleteDKIM2FIFOContext(options, state, *record, now); err != nil {
			return err
		}
	}
}

func reclaimDKIM2FIFO(options config.DKIM2ForwardingConfig, state *dkim2StoreState, needed int64, keys []string, now int64) error {
	for _, key := range keys {
		for options.MaxStoredBytesPerRecipient > 0 && state.RecipientBytes[key] > options.MaxStoredBytesPerRecipient-needed {
			record, err := peekDKIM2FIFO(options, state, key, now)
			if err != nil {
				return err
			}
			if record == nil {
				return fmt.Errorf("%w: recipient context store capacity exceeded", errDKIM2CacheCapacity)
			}
			if err := deleteDKIM2FIFOContext(options, state, *record, now); err != nil {
				return err
			}
		}
	}
	for state.StoredBytes > options.MaxStoredBytes-needed {
		record, err := peekDKIM2FIFO(options, state, "", now)
		if err != nil {
			return err
		}
		if record == nil {
			return errDKIM2CacheCapacity
		}
		if err := deleteDKIM2FIFOContext(options, state, *record, now); err != nil {
			return err
		}
	}
	return nil
}

// Once stale records are at least half the index, rebuilding that FIFO costs
// amortized O(1) per removed record. A small floor avoids constant rewrites.
func compactDKIM2FIFO(options config.DKIM2ForwardingConfig, state *dkim2StoreState, key string) error {
	queue := getDKIM2FIFO(state, key)
	if queue.Tail <= dkim2FIFOCompactBytes || queue.Tail/dkim2FIFORecordBytes <= 2*queue.Live {
		return nil
	}
	file, err := openDKIM2ContextFile(dkim2FIFOPath(options, key), os.O_RDONLY)
	if err != nil {
		return err
	}
	defer file.Close()
	temporary, err := os.CreateTemp(options.StoreDirectory, ".tmp-fifo-")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	reader := bufio.NewReader(io.NewSectionReader(file, queue.Head, queue.Tail-queue.Head))
	var data [dkim2FIFORecordBytes]byte
	var count int64
	for {
		_, err := io.ReadFull(reader, data[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return errDKIM2FIFOInvalid
			}
			return fmt.Errorf("read DKIM2 FIFO index: %w", err)
		}
		record, err := decodeDKIM2FIFORecord(data[:])
		if err != nil {
			return err
		}
		context, err := openDKIM2ContextFile(filepath.Join(options.StoreDirectory, record.ID+".ctx"), os.O_RDONLY)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		_ = context.Close()
		if _, err := temporary.Write(data[:]); err != nil {
			return err
		}
		count++
	}
	if count != queue.Live {
		return errDKIM2FIFOInvalid
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary.Name(), dkim2FIFOPath(options, key)); err != nil {
		return err
	}
	setDKIM2FIFO(state, key, dkim2FIFOState{Tail: count * dkim2FIFORecordBytes, Live: count})
	return nil
}

func compactDKIM2FIFOs(options config.DKIM2ForwardingConfig, state *dkim2StoreState) error {
	if err := compactDKIM2FIFO(options, state, ""); err != nil {
		return err
	}
	for key := range state.RecipientFIFO {
		if err := compactDKIM2FIFO(options, state, key); err != nil {
			return err
		}
	}
	return nil
}

func rebuildDKIM2FIFOs(options config.DKIM2ForwardingConfig, state *dkim2StoreState, records []dkim2FIFORecord) error {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Created != records[j].Created {
			return records[i].Created < records[j].Created
		}
		if records[i].Order != records[j].Order {
			return records[i].Order < records[j].Order
		}
		return records[i].ID < records[j].ID
	})
	state.FIFO = dkim2FIFOState{}
	state.RecipientFIFO = nil
	// The caller has marked .state dirty, so interrupted truncation is rebuilt.
	paths := map[string]bool{"": true}
	for _, record := range records {
		for _, key := range record.QuotaKeys {
			paths[key] = true
		}
	}
	entries, err := os.ReadDir(options.StoreDirectory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !dkim2FIFOName(entry.Name()) || entry.Name() == ".fifo" {
			continue
		}
		key := strings.TrimPrefix(entry.Name(), ".fifo-")
		if paths[key] {
			continue
		}
		path := filepath.Join(options.StoreDirectory, entry.Name())
		file, err := openDKIM2ContextFile(path, os.O_RDONLY)
		if err != nil {
			return err
		}
		_ = file.Close()
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	for key := range paths {
		file, err := openDKIM2ContextFile(dkim2FIFOPath(options, key), os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			return err
		}
		_ = file.Close()
	}
	// Buffer appends per FIFO during rebuild instead of fsync per context.
	for key := range paths {
		file, err := openDKIM2ContextFile(dkim2FIFOPath(options, key), os.O_WRONLY)
		if err != nil {
			return err
		}
		writer := bufio.NewWriter(file)
		var count int64
		for _, record := range records {
			include := key == ""
			for _, quota := range record.QuotaKeys {
				if quota == key {
					include = true
					break
				}
			}
			if !include {
				continue
			}
			if _, err := writer.Write(encodeDKIM2FIFORecord(record)); err != nil {
				_ = file.Close()
				return err
			}
			count++
		}
		if err := writer.Flush(); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		setDKIM2FIFO(state, key, dkim2FIFOState{Tail: count * dkim2FIFORecordBytes, Live: count})
	}
	return nil
}
