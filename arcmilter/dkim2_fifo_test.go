package arcmilter

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/masa23/arcmilter/config"
)

func assertDKIM2CacheMiss(t *testing.T, options config.DKIM2ForwardingConfig, id string) {
	t.Helper()
	if _, err := loadDKIM2ForwardContext(options, id); !errors.Is(err, errDKIM2CacheMiss) {
		t.Fatalf("expected cache miss for %s, got %v", id, err)
	}
}

func TestDKIM2ForwardStoreFIFORecipientIsolation(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	envelope.RcptTo = []string{"<a@relay.example>"}
	size := dkim2StoreContextSize(t, options, envelope, raw)
	options.CacheFailureAction, options.MaxStoredBytes = "skip-signing", 10*size
	options.MaxStoredBytesPerRecipient, options.ForwardRecipients = 2*size, []string{"a@relay.example", "b@relay.example"}
	other := envelope
	other.RcptTo = []string{"<b@relay.example>"}
	keptOther := saveDKIM2StoreFixture(t, options, other, raw)
	first := saveDKIM2StoreFixture(t, options, envelope, raw)
	second := saveDKIM2StoreFixture(t, options, envelope, raw)
	third := saveDKIM2StoreFixture(t, options, envelope, raw)
	assertDKIM2CacheMiss(t, options, first)
	for _, id := range []string{keptOther, second, third} {
		if _, err := loadDKIM2ForwardContext(options, id); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDKIM2ForwardStoreOversizedEntryDoesNotEvict(t *testing.T) {
	for _, quota := range []bool{false, true} {
		t.Run(map[bool]string{false: "global", true: "recipient"}[quota], func(t *testing.T) {
			options, envelope, raw := dkim2StoreFixture(t)
			size := dkim2StoreContextSize(t, options, envelope, raw)
			options.CacheFailureAction, options.MaxStoredBytes = "skip-signing", size
			if quota {
				options.MaxStoredBytes = 10 * size
				options.MaxStoredBytesPerRecipient = size
				options.ForwardRecipients = []string{"*@relay.example"}
			}
			kept := saveDKIM2StoreFixture(t, options, envelope, raw)
			if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, append(bytes.Clone(raw), bytes.Repeat([]byte("x"), int(size))...)); !errors.Is(err, errDKIM2CacheCapacity) {
				t.Fatalf("oversized error: %v", err)
			}
			if _, err := loadDKIM2ForwardContext(options, kept); err != nil {
				t.Fatalf("oversized save evicted original: %v", err)
			}
		})
	}
}

func TestDKIM2ForwardStoreIdleExpiryBoundary(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	options.MaxAgeSeconds = 86400
	if err := cleanupExpiredDKIM2ForwardContexts(options, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(options.StoreDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("idle GC created unused store: %v", err)
	}
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid {
		t.Fatal(err)
	}
	if err := cleanupExpiredDKIM2ForwardContexts(options, state.NextExpiry-1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(options.StoreDirectory, id+".ctx")); err != nil {
		t.Fatal(err)
	}
	if err := cleanupExpiredDKIM2ForwardContexts(options, state.NextExpiry); err != nil {
		t.Fatal(err)
	}
	assertDKIM2CacheMiss(t, options, id)
	state, valid, err = readDKIM2StoreState(options)
	if err != nil || !valid || state.StoredBytes != 0 || state.FIFO.Live != 0 {
		t.Fatalf("expired accounting: %+v %v", state, err)
	}
}

func TestDKIM2ForwardStoreIdleGCSkipsBusyLock(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	lock, err := lockDKIM2Store(options, false)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockDKIM2Store(lock)
	if err := cleanupExpiredDKIM2ForwardContexts(options, 1<<40); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDKIM2ForwardContext(options, id); err != nil {
		t.Fatal(err)
	}
}

func TestDKIM2ForwardStoreFIFOConcurrentEvictionAndLoad(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	size := dkim2StoreContextSize(t, options, envelope, raw)
	options.CacheFailureAction, options.MaxStoredBytes = "skip-signing", 2*size
	var wait sync.WaitGroup
	for i := 0; i < 16; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			id, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := loadDKIM2ForwardContext(options, id); err != nil && !errors.Is(err, errDKIM2CacheMiss) {
				t.Error(err)
			}
		}()
	}
	wait.Wait()
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid || state.StoredBytes != 2*size || state.FIFO.Live != 2 {
		t.Fatalf("concurrent accounting: %+v valid=%v err=%v", state, valid, err)
	}
}

func TestDKIM2ForwardStoreFIFORebuildsBrokenIndex(t *testing.T) {
	for _, corruption := range []string{"truncated", "checksum", "missing", "legacy"} {
		t.Run(corruption, func(t *testing.T) {
			options, envelope, raw := dkim2StoreFixture(t)
			size := dkim2StoreContextSize(t, options, envelope, raw)
			options.CacheFailureAction, options.MaxStoredBytes = "skip-signing", 2*size
			first := saveDKIM2StoreFixture(t, options, envelope, raw)
			second := saveDKIM2StoreFixture(t, options, envelope, raw)
			path := dkim2FIFOPath(options, "")
			switch corruption {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.Truncate(path, dkim2FIFORecordBytes-1); err != nil {
					t.Fatal(err)
				}
			case "checksum":
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = file.WriteAt([]byte{0xff}, 0)
				file.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "legacy":
				alterDKIM2StoreMetadata(t, options, first, func(metadata *dkim2ContextMetadata) { metadata.Order = 0; metadata.Created -= 1 })
				alterDKIM2StoreMetadata(t, options, second, func(metadata *dkim2ContextMetadata) { metadata.Order = 0 })
				if err := os.Remove(filepath.Join(options.StoreDirectory, ".state")); err != nil {
					t.Fatal(err)
				}
			}
			third := saveDKIM2StoreFixture(t, options, envelope, raw)
			assertDKIM2CacheMiss(t, options, first)
			for _, id := range []string{second, third} {
				if _, err := loadDKIM2ForwardContext(options, id); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestDKIM2ForwardStoreFIFOCompactionBoundsIndex(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	size := dkim2StoreContextSize(t, options, envelope, raw)
	options.CacheFailureAction, options.MaxStoredBytes = "skip-signing", 2*size
	options.MaxStoredBytesPerRecipient, options.ForwardRecipients = 2*size, []string{"*@relay.example"}
	for i := 0; i < 800; i++ {
		saveDKIM2StoreFixture(t, options, envelope, raw)
	}
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid {
		t.Fatal(err)
	}
	for _, queue := range []dkim2FIFOState{state.FIFO, state.RecipientFIFO[dkim2StoreQuotaKey("*@relay.example")]} {
		if queue.Live != 2 || queue.Tail > dkim2FIFOCompactBytes+2*dkim2FIFORecordBytes {
			t.Fatalf("unbounded index: %+v", queue)
		}
	}
}

func TestDKIM2ForwardStoreFIFOCapacity(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	size := dkim2StoreContextSize(t, options, envelope, raw)
	options.CacheFailureAction, options.MaxStoredBytes = "skip-signing", 3*size
	first := saveDKIM2StoreFixture(t, options, envelope, raw)
	second := saveDKIM2StoreFixture(t, options, envelope, raw)
	third := saveDKIM2StoreFixture(t, options, envelope, raw)
	marked, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid {
		t.Fatal(err)
	}
	marked.ScannedAt -= 60
	if err := writeDKIM2StoreState(options, marked); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDKIM2ForwardContext(options, first); err != nil {
		t.Fatal(err)
	}
	fourth := saveDKIM2StoreFixture(t, options, envelope, raw)
	assertDKIM2CacheMiss(t, options, first)
	for _, id := range []string{second, third, fourth} {
		if _, err := loadDKIM2ForwardContext(options, id); err != nil {
			t.Fatal(err)
		}
	}
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid || state.StoredBytes != 3*size || state.FIFO.Live != 3 || state.ScannedAt != marked.ScannedAt {
		t.Fatalf("bad FIFO accounting: %+v valid=%v err=%v", state, valid, err)
	}
}

func TestDKIM2ForwardStoreFIFORebuildRemovesOrphanQuota(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	options.ForwardRecipients = []string{"*@relay.example"}
	saveDKIM2StoreFixture(t, options, envelope, raw)
	oldPath := dkim2FIFOPath(options, dkim2StoreQuotaKey("*@relay.example"))
	options.ForwardRecipients = []string{"bob@relay.example"}
	saveDKIM2StoreFixture(t, options, envelope, raw)
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old quota index remains: %v", err)
	}
	if _, err := os.Stat(dkim2FIFOPath(options, dkim2StoreQuotaKey("bob@relay.example"))); err != nil {
		t.Fatal(err)
	}
}

func TestDKIM2ForwardStoreFIFORejectsLinkedIndex(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	saveDKIM2StoreFixture(t, options, envelope, raw)
	path := dkim2FIFOPath(options, "")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil || errors.Is(err, errDKIM2CacheMiss) {
		t.Fatalf("linked index accepted: %v", err)
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("outside changed: %q %v", data, err)
	}
}

func TestDKIM2ForwardStoreConcurrentGCAndSave(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	options.CacheFailureAction = "skip-signing"
	old := saveDKIM2StoreFixture(t, options, envelope, raw)
	alterDKIM2StoreMetadata(t, options, old, func(metadata *dkim2ContextMetadata) {
		metadata.Created -= config.DefaultDKIM2ForwardingMaxAgeSeconds + 1
	})
	if err := os.Remove(filepath.Join(options.StoreDirectory, ".state")); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for i := 0; i < 16; i++ {
		wait.Add(2)
		go func() {
			defer wait.Done()
			if err := cleanupExpiredDKIM2ForwardContexts(options, time.Now().Unix()); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wait.Done()
			if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err != nil {
				t.Error(err)
			}
		}()
	}
	wait.Wait()
	assertDKIM2CacheMiss(t, options, old)
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid || state.FIFO.Live != 16 {
		t.Fatalf("GC/save accounting: %+v %v", state, err)
	}
}

func TestDKIM2ForwardStoreFIFOIntersectingQuotas(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	envelope.RcptTo = []string{"<a@relay.example>"}
	size := dkim2StoreContextSize(t, options, envelope, raw)
	options.CacheFailureAction, options.MaxStoredBytes = "skip-signing", 10*size
	options.MaxStoredBytesPerRecipient, options.ForwardRecipients = 2*size, []string{"a@relay.example", "*@relay.example"}
	old := saveDKIM2StoreFixture(t, options, envelope, raw)
	for _, recipient := range []string{"<b@relay.example>", "<c@relay.example>"} {
		other := envelope
		other.RcptTo = []string{recipient}
		saveDKIM2StoreFixture(t, options, other, raw)
	}
	assertDKIM2CacheMiss(t, options, old)
	first := saveDKIM2StoreFixture(t, options, envelope, raw)
	second := saveDKIM2StoreFixture(t, options, envelope, raw)
	third := saveDKIM2StoreFixture(t, options, envelope, raw)
	assertDKIM2CacheMiss(t, options, first)
	for _, id := range []string{second, third} {
		if _, err := loadDKIM2ForwardContext(options, id); err != nil {
			t.Fatal(err)
		}
	}
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid {
		t.Fatal(err)
	}
	for _, rule := range options.ForwardRecipients {
		key := dkim2StoreQuotaKey(rule)
		if state.RecipientBytes[key] != 2*size || state.RecipientFIFO[key].Live != 2 {
			t.Fatalf("intersecting quota %s inconsistent: %+v", rule, state)
		}
	}
}

func TestDKIM2ForwardStoreFIFORebuildsChangedRecipientAssignment(t *testing.T) {
	options, bob, raw := dkim2StoreFixture(t)
	size := dkim2StoreContextSize(t, options, bob, raw)
	options.CacheFailureAction = "skip-signing"
	options.MaxStoredBytes = 2 * size
	options.MaxStoredBytesPerRecipient = 2 * size
	options.ForwardRecipients = []string{"bob@relay.example", "car@relay.example"}
	car := bob
	car.RcptTo = []string{"<car@relay.example>"}
	changed := saveDKIM2StoreFixture(t, options, bob, raw)
	kept := saveDKIM2StoreFixture(t, options, car, raw)
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid {
		t.Fatalf("initial state: valid=%v err=%v", valid, err)
	}
	record, err := peekDKIM2FIFO(options, &state, "", time.Now().Unix())
	if err != nil || record == nil || record.ID != changed {
		t.Fatalf("initial FIFO: record=%+v err=%v", record, err)
	}
	path := filepath.Join(options.StoreDirectory, changed+".ctx")
	alterDKIM2StoreMetadata(t, options, changed, func(metadata *dkim2ContextMetadata) {
		metadata.Envelope.RcptTo = car.RcptTo
	})
	if info, err := os.Stat(path); err != nil || info.Size() != size {
		t.Fatalf("fixture changed context size: info=%v err=%v", info, err)
	}
	if _, err := peekDKIM2FIFO(options, &state, "", time.Now().Unix()); !errors.Is(err, errDKIM2FIFOInvalid) {
		t.Fatalf("changed quota assignment was not detected by peek: %v", err)
	}
	if err := deleteDKIM2FIFOContext(options, &state, *record, time.Now().Unix()); !errors.Is(err, errDKIM2FIFOInvalid) {
		t.Fatalf("changed quota assignment was not detected by delete: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("mismatched context was deleted: %v", err)
	}
	replacement := saveDKIM2StoreFixture(t, options, bob, raw)
	assertDKIM2CacheMiss(t, options, changed)
	for _, id := range []string{kept, replacement} {
		if _, err := loadDKIM2ForwardContext(options, id); err != nil {
			t.Fatal(err)
		}
	}
	state, valid, err = readDKIM2StoreState(options)
	if err != nil || !valid || state.StoredBytes != 2*size ||
		state.RecipientBytes[dkim2StoreQuotaKey("bob@relay.example")] != size ||
		state.RecipientBytes[dkim2StoreQuotaKey("car@relay.example")] != size {
		t.Fatalf("rebuild left incorrect quota accounting: state=%+v valid=%v err=%v", state, valid, err)
	}
}

func TestDKIM2ForwardStoreFIFORejectsRecordFromOtherQuota(t *testing.T) {
	options, bob, raw := dkim2StoreFixture(t)
	size := dkim2StoreContextSize(t, options, bob, raw)
	options.CacheFailureAction = "skip-signing"
	options.MaxStoredBytes = 3 * size
	options.MaxStoredBytesPerRecipient = size
	options.ForwardRecipients = []string{"bob@relay.example", "car@relay.example"}
	car := bob
	car.RcptTo = []string{"<car@relay.example>"}
	oldBob := saveDKIM2StoreFixture(t, options, bob, raw)
	keptCar := saveDKIM2StoreFixture(t, options, car, raw)
	bobKey := dkim2StoreQuotaKey("bob@relay.example")
	carKey := dkim2StoreQuotaKey("car@relay.example")
	otherRecord, err := os.ReadFile(dkim2FIFOPath(options, carKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(otherRecord) != int(dkim2FIFORecordBytes) {
		t.Fatalf("unexpected quota FIFO length: %d", len(otherRecord))
	}
	if err := os.WriteFile(dkim2FIFOPath(options, bobKey), otherRecord, 0600); err != nil {
		t.Fatal(err)
	}
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid {
		t.Fatalf("initial state: valid=%v err=%v", valid, err)
	}
	if _, err := peekDKIM2FIFO(options, &state, bobKey, time.Now().Unix()); !errors.Is(err, errDKIM2FIFOInvalid) {
		t.Fatalf("foreign quota record was accepted: %v", err)
	}
	replacement := saveDKIM2StoreFixture(t, options, bob, raw)
	assertDKIM2CacheMiss(t, options, oldBob)
	for _, id := range []string{keptCar, replacement} {
		if _, err := loadDKIM2ForwardContext(options, id); err != nil {
			t.Fatal(err)
		}
	}
	state, valid, err = readDKIM2StoreState(options)
	if err != nil || !valid || state.StoredBytes != 2*size ||
		state.RecipientBytes[bobKey] != size || state.RecipientBytes[carKey] != size {
		t.Fatalf("rebuild left incorrect quota accounting: state=%+v valid=%v err=%v", state, valid, err)
	}
}

func TestDKIM2ForwardStoreFIFORejectsSameSizeCorruptMetadata(t *testing.T) {
	for _, operation := range []string{"peek", "delete", "save"} {
		for _, corruption := range []string{"missing recipients", "raw length", "JSON"} {
			t.Run(operation+"/"+corruption, func(t *testing.T) {
				options, envelope, raw := dkim2StoreFixture(t)
				options.CacheFailureAction = "skip-signing"
				options.ForwardRecipients = []string{"bob@relay.example", "car@relay.example"}
				size := dkim2StoreContextSize(t, options, envelope, raw)
				options.MaxStoredBytes, options.MaxStoredBytesPerRecipient = size, size
				id := saveDKIM2StoreFixture(t, options, envelope, raw)
				state, valid, err := readDKIM2StoreState(options)
				if err != nil || !valid {
					t.Fatalf("initial state invalid: %v", err)
				}
				now := time.Now().Unix()
				record, err := peekDKIM2FIFO(options, &state, "", now)
				if err != nil || record == nil {
					t.Fatalf("initial FIFO unavailable: %v", err)
				}
				path := filepath.Join(options.StoreDirectory, id+".ctx")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				before, body, ok := bytes.Cut(data, []byte("\n"))
				if !ok {
					t.Fatal("fixture has no metadata line")
				}
				var metadata dkim2ContextMetadata
				if err := json.Unmarshal(before, &metadata); err != nil {
					t.Fatal(err)
				}
				line := []byte("not-json")
				if corruption != "JSON" {
					if corruption == "missing recipients" {
						metadata.Envelope.RcptTo = nil
					} else {
						metadata.RawBytes++
					}
					line, err = json.Marshal(metadata)
					if err != nil {
						t.Fatal(err)
					}
				}
				if len(line) > len(before) {
					t.Fatal("corrupt fixture grew")
				}
				line = append(line, bytes.Repeat([]byte(" "), len(before)-len(line))...)
				if err := os.WriteFile(path, append(append(line, '\n'), body...), 0600); err != nil {
					t.Fatal(err)
				}
				switch operation {
				case "peek":
					_, err = peekDKIM2FIFO(options, &state, "", now)
				case "delete":
					err = deleteDKIM2FIFOContext(options, &state, *record, now)
				case "save":
					envelope.RcptTo = []string{"<car@relay.example>"}
					_, err = saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw)
				}
				if !errors.Is(err, errDKIM2ContextMetadata) {
					t.Fatalf("corruption was accepted: %v", err)
				}
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("unexpired corrupt original was deleted: %v", err)
				}
				if operation == "save" {
					state, valid, err = readDKIM2StoreState(options)
					if err != nil || valid && !state.Dirty {
						t.Fatalf("failed save published clean state: valid=%v state=%+v err=%v", valid, state, err)
					}
				} else if state.StoredBytes != record.Size || state.RecipientBytes[dkim2StoreQuotaKey("bob@relay.example")] != record.Size || state.FIFO.Live != 1 {
					t.Fatalf("failed FIFO operation changed accounting: %+v", state)
				}
			})
		}
	}
}

func TestDKIM2ForwardStoreFIFORecoversExpiredCorruptMetadata(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	options.MaxAgeSeconds = 60
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	path := filepath.Join(options.StoreDirectory, id+".ctx")
	if err := os.WriteFile(path, []byte("not-json\nbody"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-120 * time.Second)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	// Keep the accounting inode and size checks valid. GC must notice the
	// corrupt head itself and rebuild rather than wait for another save.
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid {
		t.Fatal(err)
	}
	if err := cleanupExpiredDKIM2ForwardContexts(options, state.NextExpiry); err != nil {
		t.Fatalf("expired corrupt head prevented GC: %v", err)
	}
	assertDKIM2CacheMiss(t, options, id)
	state, valid, err = readDKIM2StoreState(options)
	if err != nil || !valid || state.Dirty || state.StoredBytes != 0 || state.FIFO.Live != 0 {
		t.Fatalf("recovered FIFO state inconsistent: valid=%v state=%+v err=%v", valid, state, err)
	}
}
