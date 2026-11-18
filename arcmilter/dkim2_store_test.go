package arcmilter

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/iotest"
	"time"

	"github.com/masa23/arcmilter/config"
	"github.com/masa23/mmauth/dkim2"
)

func dkim2StoreFixture(t testing.TB) (config.DKIM2ForwardingConfig, dkim2.Envelope, []byte) {
	t.Helper()
	return config.DKIM2ForwardingConfig{StoreDirectory: filepath.Join(t.TempDir(), "contexts"), CacheFailureAction: "tempfail"},
		dkim2.Envelope{MailFrom: "<alice@example.com>", RcptTo: []string{"<bob@relay.example>"}},
		[]byte("From: alice@example.com\r\nTo: bob@relay.example\r\n\r\nbody\r\n")
}

func saveDKIM2StoreFixture(t testing.TB, options config.DKIM2ForwardingConfig, envelope dkim2.Envelope, raw []byte) string {
	t.Helper()
	id, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestDKIM2ForwardStoreRollbackReleasesOnlyNewContext(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	kept := saveDKIM2StoreFixture(t, options, envelope, raw)
	info, err := os.Stat(filepath.Join(options.StoreDirectory, kept+".ctx"))
	if err != nil {
		t.Fatal(err)
	}
	options.MaxStoredBytes = 2 * info.Size()
	rolledBack := saveDKIM2StoreFixture(t, options, envelope, raw)
	if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil {
		t.Fatal("full store accepted another context")
	}
	for i := 0; i < 2; i++ {
		if err := removeDKIM2ForwardContext(options, rolledBack); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loadDKIM2ForwardContext(options, rolledBack); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rolled-back context remains available: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := loadDKIM2ForwardContext(options, kept); err != nil {
			t.Fatalf("rollback removed a previously accepted context: %v", err)
		}
	}
	replacement := saveDKIM2StoreFixture(t, options, envelope, raw)
	if _, err := loadDKIM2ForwardContext(options, replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil {
		t.Fatal("repeated rollback incorrectly reduced accounted bytes")
	}
	if err := removeDKIM2ForwardContext(options, "../outside"); err == nil {
		t.Fatal("rollback accepted an invalid ID")
	}
}

func TestDKIM2ForwardStoreRollbackRebuildsChangedRecipientAssignment(t *testing.T) {
	options, bob, raw := dkim2StoreFixture(t)
	size := dkim2StoreContextSize(t, options, bob, raw)
	options.MaxStoredBytes = 3 * size
	options.MaxStoredBytesPerRecipient = 3 * size
	options.ForwardRecipients = []string{"bob@relay.example", "car@relay.example"}
	car := bob
	car.RcptTo = []string{"<car@relay.example>"}
	kept := saveDKIM2StoreFixture(t, options, car, raw)
	rolledBack := saveDKIM2StoreFixture(t, options, bob, raw)
	alterDKIM2StoreMetadata(t, options, rolledBack, func(metadata *dkim2ContextMetadata) {
		metadata.Envelope.RcptTo = car.RcptTo
	})
	if err := removeDKIM2ForwardContext(options, rolledBack); err != nil {
		t.Fatal(err)
	}
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid || state.StoredBytes != size ||
		state.RecipientBytes[dkim2StoreQuotaKey("bob@relay.example")] != 0 ||
		state.RecipientBytes[dkim2StoreQuotaKey("car@relay.example")] != size {
		t.Fatalf("rollback left incorrect quota accounting: state=%+v valid=%v err=%v", state, valid, err)
	}
	if _, err := loadDKIM2ForwardContext(options, kept); err != nil {
		t.Fatalf("rollback removed the other context: %v", err)
	}
	if _, err := saveDKIM2ForwardContext(options, bob, []string{"relay.example"}, raw); err != nil {
		t.Fatalf("released quota was unavailable: %v", err)
	}
}

func TestDKIM2ForwardStoreRebuildsInterruptedOrCorruptAccounting(t *testing.T) {
	for _, kind := range []string{"missing", "truncated", "checksum", "dirty", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			options, envelope, raw := dkim2StoreFixture(t)
			id := saveDKIM2StoreFixture(t, options, envelope, raw)
			info, err := os.Stat(filepath.Join(options.StoreDirectory, id+".ctx"))
			if err != nil {
				t.Fatal(err)
			}
			options.MaxStoredBytes = info.Size()
			statePath := filepath.Join(options.StoreDirectory, ".state")
			switch kind {
			case "missing":
				err = os.Remove(statePath)
			case "truncated":
				err = os.WriteFile(statePath, []byte(`{"version":`), 0600)
			case "oversized":
				err = os.WriteFile(statePath, bytes.Repeat([]byte{'x'}, dkim2StoreStateLimit+1), 0600)
			default:
				state, valid, readErr := readDKIM2StoreState(options)
				if readErr != nil || !valid {
					t.Fatalf("initial state unavailable: %v", readErr)
				}
				state.StoredBytes = 0 // 途中の操作や破損で使用量が過少になった状態。
				if kind == "dirty" {
					state.Dirty = true
					err = writeDKIM2StoreState(options, state)
				} else {
					var data []byte
					data, err = json.Marshal(state) // 元の checksum は更新しない。
					if err == nil {
						err = os.WriteFile(statePath, data, 0600)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil {
				t.Fatal("broken accounting allowed capacity to be exceeded")
			}
			if _, err := loadDKIM2ForwardContext(options, id); err != nil {
				t.Fatal(err)
			}
			if err := removeDKIM2ForwardContext(options, id); err != nil {
				t.Fatal(err)
			}
			saveDKIM2StoreFixture(t, options, envelope, raw)
		})
	}
}

func TestDKIM2ForwardStoreRebuildAfterInterruptedDeletion(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	path := filepath.Join(options.StoreDirectory, id+".ctx")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	options.MaxStoredBytes = info.Size()
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid {
		t.Fatalf("initial state unavailable: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	state.Dirty = true
	if err := writeDKIM2StoreState(options, state); err != nil {
		t.Fatal(err)
	}
	saveDKIM2StoreFixture(t, options, envelope, raw)
}

func TestDKIM2ForwardStoreRebuildAfterInterruptedWrite(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	contents, err := os.ReadFile(filepath.Join(options.StoreDirectory, id+".ctx"))
	if err != nil {
		t.Fatal(err)
	}
	options.MaxStoredBytes = int64(2 * len(contents))
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid {
		t.Fatalf("initial state unavailable: %v", err)
	}
	// 完全な ctx の rename 後、使用量を確定する前に中断した状態を再現する。
	newID := strings.Repeat("b", 64)
	if err := os.WriteFile(filepath.Join(options.StoreDirectory, newID+".ctx"), contents, 0600); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(options.StoreDirectory, ".tmp-interrupted")
	if err := os.WriteFile(temporary, []byte("unfinished write"), 0600); err != nil {
		t.Fatal(err)
	}
	state.Dirty = true
	if err := writeDKIM2StoreState(options, state); err != nil {
		t.Fatal(err)
	}
	if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil {
		t.Fatal("unaccounted completed write exceeded capacity")
	}
	if _, err := os.Stat(temporary); !os.IsNotExist(err) {
		t.Fatalf("interrupted temporary file remains: %v", err)
	}
	if _, err := loadDKIM2ForwardContext(options, newID); err != nil {
		t.Fatalf("completed context was lost during recovery: %v", err)
	}
}

func TestDKIM2ForwardStoreRejectsLinkedAccounting(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	saveDKIM2StoreFixture(t, options, envelope, raw)
	statePath := filepath.Join(options.StoreDirectory, ".state")
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	contents := []byte("must not be read or truncated")
	if err := os.WriteFile(outside, contents, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil {
		t.Fatal("linked accounting state was accepted")
	}
	got, err := os.ReadFile(outside)
	if err != nil || !bytes.Equal(got, contents) {
		t.Fatalf("outside file changed: contents=%q err=%v", got, err)
	}
}

func TestDKIM2ForwardStoreRejectsHardLinkedAccounting(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	saveDKIM2StoreFixture(t, options, envelope, raw)
	statePath := filepath.Join(options.StoreDirectory, ".state")
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	contents := []byte("must not be truncated through a hard link")
	if err := os.WriteFile(outside, contents, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, statePath); err != nil {
		t.Fatal(err)
	}
	if err := writeDKIM2StoreState(options, dkim2StoreState{}); err == nil {
		t.Fatal("hard-linked state was truncated before validation")
	}
	if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil {
		t.Fatal("hard-linked accounting state was accepted")
	}
	got, err := os.ReadFile(outside)
	if err != nil || !bytes.Equal(got, contents) {
		t.Fatalf("outside file changed: contents=%q err=%v", got, err)
	}
}

func TestDKIM2ForwardStoreRejectsForeignOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires root")
	}
	for _, target := range []string{"directory", "state", "context"} {
		t.Run(target, func(t *testing.T) {
			options, envelope, raw := dkim2StoreFixture(t)
			id := saveDKIM2StoreFixture(t, options, envelope, raw)
			path := options.StoreDirectory
			switch target {
			case "state":
				path = filepath.Join(path, ".state")
			case "context":
				path = filepath.Join(path, id+".ctx")
			}
			if err := os.Chown(path, 65534, -1); err != nil {
				if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
					t.Skipf("changing file ownership is unavailable: %v", err)
				}
				t.Fatal(err)
			}
			if target == "context" {
				if _, err := loadDKIM2ForwardContext(options, id); err == nil {
					t.Fatal("foreign-owned context was read")
				}
			} else if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil {
				t.Fatal("foreign-owned store entry was accepted")
			}
		})
	}
}

func TestDKIM2ForwardStoreRejectsUntrustedParent(t *testing.T) {
	for _, setup := range []struct {
		name string
		make func(*testing.T, string) string
	}{
		{"group writable", func(t *testing.T, base string) string {
			parent := filepath.Join(base, "parent")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(parent, 0770); err != nil {
				t.Fatal(err)
			}
			return parent
		}},
		{"symlink to group writable", func(t *testing.T, base string) string {
			parent := filepath.Join(base, "parent")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(parent, 0770); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(base, "alias")
			if err := os.Symlink(parent, alias); err != nil {
				t.Fatal(err)
			}
			return alias
		}},
		{"foreign owner", func(t *testing.T, base string) string {
			if os.Geteuid() != 0 {
				t.Skip("changing directory ownership requires root")
			}
			parent := filepath.Join(base, "parent")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(parent, 65534, -1); err != nil {
				if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
					t.Skipf("changing directory ownership is unavailable: %v", err)
				}
				t.Fatal(err)
			}
			return parent
		}},
	} {
		t.Run(setup.name, func(t *testing.T) {
			base := t.TempDir()
			parent := setup.make(t, base)
			options, envelope, raw := dkim2StoreFixture(t)
			options.StoreDirectory = filepath.Join(parent, "contexts")
			if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil {
				t.Fatal("untrusted parent was accepted")
			}
		})
	}
}

func TestDKIM2ForwardStoreAcceptsTrustedParentSymlink(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(parent, alias); err != nil {
		t.Fatal(err)
	}
	options, envelope, raw := dkim2StoreFixture(t)
	options.StoreDirectory = filepath.Join(alias, "contexts")
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	if _, err := loadDKIM2ForwardContext(options, id); err != nil {
		t.Fatal(err)
	}
}

func TestDKIM2ForwardStoreConcurrentRollback(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	info, err := os.Stat(filepath.Join(options.StoreDirectory, id+".ctx"))
	if err != nil {
		t.Fatal(err)
	}
	if err := removeDKIM2ForwardContext(options, id); err != nil {
		t.Fatal(err)
	}
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
			if err := removeDKIM2ForwardContext(options, id); err != nil {
				t.Error(err)
			}
		}()
	}
	wait.Wait()
	options.MaxStoredBytes = info.Size()
	saveDKIM2StoreFixture(t, options, envelope, raw)
	if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil {
		t.Fatal("concurrent rollback corrupted quota accounting")
	}
}

func seedDKIM2StoreContexts(t testing.TB, options config.DKIM2ForwardingConfig, envelope dkim2.Envelope, raw []byte, count int) {
	t.Helper()
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	contents, err := os.ReadFile(filepath.Join(options.StoreDirectory, id+".ctx"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < count; i++ {
		path := filepath.Join(options.StoreDirectory, fmt.Sprintf("%064x.ctx", i))
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// 外部で作った fixture は、計測前の1回の再計算で管理情報へ取り込む。
	id = saveDKIM2StoreFixture(t, options, envelope, raw)
	if err := removeDKIM2ForwardContext(options, id); err != nil {
		t.Fatal(err)
	}
}

func TestDKIM2ForwardStoreSaveAllocationsDoNotScaleWithRetainedContexts(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	measure := func() float64 {
		return testing.AllocsPerRun(3, func() {
			id := saveDKIM2StoreFixture(t, options, envelope, raw)
			if err := removeDKIM2ForwardContext(options, id); err != nil {
				t.Fatal(err)
			}
		})
	}
	seedDKIM2StoreContexts(t, options, envelope, raw, 1)
	small := measure()
	seedDKIM2StoreContexts(t, options, envelope, raw, 1000)
	large := measure()
	if large > small+50 {
		t.Fatalf("retained contexts increased per-save allocations: one=%g thousand=%g", small, large)
	}
}

func BenchmarkDKIM2ForwardStoreSaveRetainedContexts(b *testing.B) {
	for _, retained := range []int{1000, 10000} {
		b.Run(fmt.Sprint(retained), func(b *testing.B) {
			options, envelope, raw := dkim2StoreFixture(b)
			seedDKIM2StoreContexts(b, options, envelope, raw, retained)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				id := saveDKIM2StoreFixture(b, options, envelope, raw)
				if err := removeDKIM2ForwardContext(options, id); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func alterDKIM2StoreMetadata(t *testing.T, options config.DKIM2ForwardingConfig, id string, alter func(*dkim2ContextMetadata)) {
	t.Helper()
	path := filepath.Join(options.StoreDirectory, id+".ctx")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line, raw, ok := bytes.Cut(contents, []byte{'\n'})
	if !ok {
		t.Fatal("stored metadata separator missing")
	}
	var metadata dkim2ContextMetadata
	if err := json.Unmarshal(line, &metadata); err != nil {
		t.Fatal(err)
	}
	alter(&metadata)
	line, err = json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	contents = append(append(line, '\n'), raw...)
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDKIM2ForwardStoreRoundTrip(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	if !validDKIM2ContextID(id) {
		t.Fatalf("context ID is not 256-bit hexadecimal: %q", id)
	}
	for i := 0; i < 2; i++ {
		context, err := loadDKIM2ForwardContext(options, id)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(context.Envelope, envelope) || !reflect.DeepEqual(context.SigningDomains, []string{"relay.example"}) || !bytes.Equal(context.Raw, raw) {
			t.Fatal("stored envelope, domains, or original bytes changed")
		}
	}
	for path, mode := range map[string]os.FileMode{
		options.StoreDirectory:                           0700,
		filepath.Join(options.StoreDirectory, id+".ctx"): 0600,
		filepath.Join(options.StoreDirectory, ".lock"):   0600,
	} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("private store permissions for %s: info=%v err=%v", path, info, err)
		}
	}
}

func TestDKIM2ForwardStoreRejectsUntrustedPaths(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	for _, id := range []string{"", ".", "../secret", "/tmp/secret", strings.Repeat("a", 63), strings.Repeat("g", 64), strings.Repeat("a", 64) + ".ctx"} {
		if _, err := loadDKIM2ForwardContext(options, id); err == nil {
			t.Fatalf("invalid context ID accepted: %q", id)
		}
	}
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	path := filepath.Join(options.StoreDirectory, id+".ctx")
	outside := filepath.Join(t.TempDir(), "outside.ctx")
	if err := os.Rename(path, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDKIM2ForwardContext(options, id); err == nil {
		t.Fatal("symlink context file was followed")
	}
	if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil {
		t.Fatal("store containing a symlink was accepted")
	}
	options.StoreDirectory = t.TempDir()
	if err := os.Chmod(options.StoreDirectory, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil {
		t.Fatal("nonprivate spool directory was accepted")
	}
}

func TestDKIM2ForwardStoreExpirationAndCapacity(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	options.MaxAgeSeconds = 60
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	info, err := os.Stat(filepath.Join(options.StoreDirectory, id+".ctx"))
	if err != nil {
		t.Fatal(err)
	}
	options.MaxStoredBytes = info.Size()
	if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil {
		t.Fatal("full spool accepted another message")
	}
	alterDKIM2StoreMetadata(t, options, id, func(metadata *dkim2ContextMetadata) { metadata.Created = time.Now().Unix() - 120 })
	// Keep the accounting information consistent with the simulated passage of
	// time so the capacity path knows that an expiry can now be reclaimed.
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid {
		t.Fatalf("initial state unavailable: %v", err)
	}
	state.NextExpiry = time.Now().Unix()
	if err := writeDKIM2StoreState(options, state); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDKIM2ForwardContext(options, id); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired context was accepted: %v", err)
	}
	newID := saveDKIM2StoreFixture(t, options, envelope, raw)
	if _, err := os.Stat(filepath.Join(options.StoreDirectory, id+".ctx")); !os.IsNotExist(err) {
		t.Fatalf("expired context was not reclaimed: %v", err)
	}
	if _, err := loadDKIM2ForwardContext(options, newID); err != nil {
		t.Fatal(err)
	}
}

func TestDKIM2ForwardStoreFullCapacityDoesNotRescanBeforeExpiry(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	info, err := os.Stat(filepath.Join(options.StoreDirectory, id+".ctx"))
	if err != nil {
		t.Fatal(err)
	}
	options.MaxStoredBytes = info.Size()
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid {
		t.Fatalf("initial state unavailable: %v", err)
	}
	marker := time.Now().Unix() - 3600
	state.ScannedAt = marker
	state.NextExpiry = time.Now().Unix() + 3600
	if err := writeDKIM2StoreState(options, state); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil ||
			!strings.Contains(err.Error(), "capacity exceeded") {
			t.Fatalf("full store attempt %d: %v", i, err)
		}
	}
	state, valid, err = readDKIM2StoreState(options)
	if err != nil || !valid {
		t.Fatalf("state unavailable after capacity attempts: %v", err)
	}
	if state.ScannedAt != marker {
		t.Fatalf("full store was rescanned before expiry: ScannedAt=%d want %d", state.ScannedAt, marker)
	}
}

func dkim2StoreContextSize(t *testing.T, options config.DKIM2ForwardingConfig, envelope dkim2.Envelope, raw []byte) int64 {
	t.Helper()
	probe := saveDKIM2StoreFixture(t, options, envelope, raw)
	info, err := os.Stat(filepath.Join(options.StoreDirectory, probe+".ctx"))
	if err != nil {
		t.Fatal(err)
	}
	if err := removeDKIM2ForwardContext(options, probe); err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func TestDKIM2ForwardStoreRecipientQuota(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	envelope.RcptTo = []string{"<forward@relay.example>"}
	size := dkim2StoreContextSize(t, options, envelope, raw)
	options.MaxStoredBytes = 10 * size
	options.MaxStoredBytesPerRecipient = size
	options.ForwardRecipients = []string{"forward@relay.example", "*@relay.example"}

	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid {
		t.Fatalf("quota state unavailable: %v", err)
	}
	for _, key := range options.ForwardRecipients {
		if got := state.RecipientBytes[dkim2StoreQuotaKey(key)]; got != size {
			t.Fatalf("quota %s = %d, want %d", key, got, size)
		}
	}

	other := envelope
	other.RcptTo = []string{"<other@relay.example>"}
	if _, err := saveDKIM2ForwardContext(options, other, []string{"relay.example"}, raw); err == nil ||
		!strings.Contains(err.Error(), "recipient context store capacity") {
		t.Fatalf("wildcard recipient quota was not enforced: %v", err)
	}
	if err := removeDKIM2ForwardContext(options, id); err != nil {
		t.Fatal(err)
	}
	if _, err := saveDKIM2ForwardContext(options, other, []string{"relay.example"}, raw); err != nil {
		t.Fatalf("rollback did not release recipient quota: %v", err)
	}
}

func TestDKIM2ForwardStoreRecipientQuotaRebuildsAccounting(t *testing.T) {
	for _, change := range []string{"missing state", "limit change"} {
		t.Run(change, func(t *testing.T) {
			options, envelope, raw := dkim2StoreFixture(t)
			envelope.RcptTo = []string{"<forward@relay.example>"}
			size := dkim2StoreContextSize(t, options, envelope, raw)
			options.MaxStoredBytes = 10 * size
			options.MaxStoredBytesPerRecipient = size
			options.ForwardRecipients = []string{"forward@relay.example"}
			if change == "limit change" {
				options.MaxStoredBytesPerRecipient = 2 * size
			}
			saveDKIM2StoreFixture(t, options, envelope, raw)

			switch change {
			case "missing state":
				if err := os.Remove(filepath.Join(options.StoreDirectory, ".state")); err != nil {
					t.Fatal(err)
				}
			case "limit change":
				state, valid, err := readDKIM2StoreState(options)
				if err != nil || !valid {
					t.Fatalf("quota state unavailable: %v", err)
				}
				// A stale usage of zero must not survive the quota policy change.
				delete(state.RecipientBytes, dkim2StoreQuotaKey("forward@relay.example"))
				if err := writeDKIM2StoreState(options, state); err != nil {
					t.Fatal(err)
				}
				options.MaxStoredBytesPerRecipient = size
			}
			if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil ||
				!strings.Contains(err.Error(), "recipient context store capacity") {
				t.Fatalf("recipient quota accounting was not rebuilt after %s: %v", change, err)
			}
		})
	}
}

func TestDKIM2ForwardStoreRecipientQuotaBoundsPolicy(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	options.MaxStoredBytesPerRecipient = 1024
	for i := 0; i <= dkim2StoreQuotaKeyLimit; i++ {
		options.ForwardRecipients = append(options.ForwardRecipients, fmt.Sprintf("forward-%d@relay.example", i))
	}
	if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); err == nil ||
		!strings.Contains(err.Error(), "too many") {
		t.Fatalf("oversized recipient quota policy was accepted: %v", err)
	}
}

func TestDKIM2ForwardStoreQuotaStateUsesBoundedKeys(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	options.MaxStoredBytesPerRecipient = options.MaxStoredBytes
	for i := 0; i < dkim2StoreQuotaKeyLimit; i++ {
		options.ForwardRecipients = append(options.ForwardRecipients,
			fmt.Sprintf("%s-%03d@relay.example", strings.Repeat("&", 100), i))
	}
	for _, recipient := range options.ForwardRecipients {
		current := envelope
		current.RcptTo = []string{"<" + recipient + ">"}
		saveDKIM2StoreFixture(t, options, current, raw)
	}
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid {
		t.Fatalf("bounded quota state unavailable: valid=%v err=%v", valid, err)
	}
	if len(state.RecipientBytes) != dkim2StoreQuotaKeyLimit {
		t.Fatalf("quota state keys=%d, want %d", len(state.RecipientBytes), dkim2StoreQuotaKeyLimit)
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > dkim2StoreStateLimit {
		t.Fatalf("quota state size=%d exceeds %d", len(encoded), dkim2StoreStateLimit)
	}
}

func TestDKIM2ForwardStoreConcurrentRecipientQuota(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	envelope.RcptTo = []string{"<forward@relay.example>"}
	size := dkim2StoreContextSize(t, options, envelope, raw)
	options.MaxStoredBytes = 16 * size
	options.MaxStoredBytesPerRecipient = size
	options.ForwardRecipients = []string{"forward@relay.example"}

	var wait sync.WaitGroup
	results := make(chan string, 16)
	for i := 0; i < 16; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			id, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw)
			if err == nil {
				results <- id
			}
		}()
	}
	wait.Wait()
	close(results)
	if len(results) != 1 {
		t.Fatalf("concurrent writers exceeded one-recipient capacity: %d accepted", len(results))
	}
}

func TestDKIM2ForwardStoreConcurrentCapacity(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	path := filepath.Join(options.StoreDirectory, id+".ctx")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	options.MaxStoredBytes = info.Size()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan string, 16)
	for i := 0; i < 16; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			id, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw)
			if err == nil {
				results <- id
			}
		}()
	}
	wait.Wait()
	close(results)
	if len(results) != 1 {
		t.Fatalf("concurrent writers exceeded one-context capacity: %d accepted", len(results))
	}
	for id := range results {
		if _, err := loadDKIM2ForwardContext(options, id); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDKIM2ForwardStoreRejectsCorruption(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*dkim2ContextMetadata)
	}{
		{"version", func(metadata *dkim2ContextMetadata) { metadata.Version = 2 }},
		{"future timestamp", func(metadata *dkim2ContextMetadata) { metadata.Created = time.Now().Unix() + 3600 }},
		{"sender", func(metadata *dkim2ContextMetadata) { metadata.Envelope.MailFrom = "" }},
		{"recipients", func(metadata *dkim2ContextMetadata) { metadata.Envelope.RcptTo = nil }},
		{"signers", func(metadata *dkim2ContextMetadata) { metadata.SigningDomains = nil }},
		{"length", func(metadata *dkim2ContextMetadata) { metadata.RawBytes++ }},
		{"oversized raw", func(metadata *dkim2ContextMetadata) { metadata.RawBytes = config.DefaultDKIM2MaxMessageBytes + 1 }},
		{"checksum", func(metadata *dkim2ContextMetadata) { metadata.SHA256 = strings.Repeat("0", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options, envelope, raw := dkim2StoreFixture(t)
			id := saveDKIM2StoreFixture(t, options, envelope, raw)
			alterDKIM2StoreMetadata(t, options, id, tc.alter)
			if _, err := loadDKIM2ForwardContext(options, id); err == nil {
				t.Fatal("corrupt context was accepted")
			}
		})
	}
	for _, contents := range [][]byte{[]byte("not-json\nbody"), bytes.Repeat([]byte{'x'}, dkim2ContextMetadataLimit+1)} {
		options, envelope, raw := dkim2StoreFixture(t)
		id := saveDKIM2StoreFixture(t, options, envelope, raw)
		if err := os.WriteFile(filepath.Join(options.StoreDirectory, id+".ctx"), contents, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadDKIM2ForwardContext(options, id); err == nil {
			t.Fatal("malformed metadata was accepted")
		}
	}
}

func TestDKIM2MetadataReadDistinguishesIOFailureFromCorruption(t *testing.T) {
	for _, prefix := range []string{"", "{\"version\":", strings.Repeat("x", 2048)} {
		reader := bufio.NewReaderSize(io.MultiReader(strings.NewReader(prefix), iotest.ErrReader(syscall.EIO)), 32)
		_, _, err := readDKIM2ContextMetadata(reader)
		if !errors.Is(err, syscall.EIO) || errors.Is(err, errDKIM2ContextMetadata) {
			t.Fatalf("read error lost its I/O identity: %v", err)
		}
	}
	for _, data := range []string{"", "{}", "not-json\nbody", "{\"signing_domains\":[\"\xff\"]}\n", strings.Repeat("x", dkim2ContextMetadataLimit+1)} {
		_, _, err := readDKIM2ContextMetadata(bufio.NewReaderSize(strings.NewReader(data), 32))
		if !errors.Is(err, errDKIM2ContextMetadata) {
			t.Fatalf("invalid metadata was not classified as corruption: %v", err)
		}
	}
}

func TestDKIM2ForwardStoreRebuildRejectsUnaccountableMetadata(t *testing.T) {
	for _, corruption := range []string{"JSON", "missing recipients", "invalid recipient", "invalid domain", "version", "signers", "order", "raw length"} {
		t.Run(corruption, func(t *testing.T) {
			options, envelope, raw := dkim2StoreFixture(t)
			options.ForwardRecipients = []string{"*@relay.example"}
			options.MaxAgeSeconds = 60
			id := saveDKIM2StoreFixture(t, options, envelope, raw)
			path := filepath.Join(options.StoreDirectory, id+".ctx")
			if corruption == "JSON" {
				if err := os.WriteFile(path, []byte("not-json\noriginal-body"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				alterDKIM2StoreMetadata(t, options, id, func(metadata *dkim2ContextMetadata) {
					switch corruption {
					case "missing recipients":
						metadata.Envelope.RcptTo = nil
					case "invalid recipient":
						metadata.Envelope.RcptTo = []string{"<not-a-mailbox>"}
					case "invalid domain":
						metadata.Envelope.RcptTo = []string{"<bob@invalid_domain>"}
					case "version":
						metadata.Version++
					case "signers":
						metadata.SigningDomains = []string{"invalid_domain"}
					case "order":
						metadata.Order = -1
					case "raw length":
						metadata.RawBytes++
					}
				})
			}
			if err := os.Remove(filepath.Join(options.StoreDirectory, ".state")); err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				if _, err := saveDKIM2ForwardContext(options, envelope, []string{"relay.example"}, raw); !errors.Is(err, errDKIM2ContextMetadata) {
					t.Fatalf("rebuild accepted unaccountable context: %v", err)
				}
				state, valid, err := readDKIM2StoreState(options)
				if err != nil || valid && !state.Dirty {
					t.Fatalf("rebuild published clean, undercounted state: valid=%v state=%+v err=%v", valid, state, err)
				}
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("unexpired corrupt context was removed: %v", err)
			}
		})
	}
}

func TestDKIM2ForwardStoreRebuildReclaimsExpiredCorruptMetadata(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	options.ForwardRecipients = []string{"*@relay.example"}
	options.MaxAgeSeconds = 60
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	path := filepath.Join(options.StoreDirectory, id+".ctx")
	if err := os.WriteFile(path, []byte("not-json\noriginal-body"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-120 * time.Second)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(options.StoreDirectory, ".state")); err != nil {
		t.Fatal(err)
	}
	newID := saveDKIM2StoreFixture(t, options, envelope, raw)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired corrupt context was not reclaimed: %v", err)
	}
	info, err := os.Stat(filepath.Join(options.StoreDirectory, newID+".ctx"))
	if err != nil {
		t.Fatal(err)
	}
	state, valid, err := readDKIM2StoreState(options)
	if err != nil || !valid || state.Dirty || state.StoredBytes != info.Size() || state.RecipientBytes[dkim2StoreQuotaKey("*@relay.example")] != info.Size() {
		t.Fatalf("recovered accounting does not match remaining context: valid=%v state=%+v err=%v", valid, state, err)
	}
}

func TestDKIM2StoredEnvelopeAcceptsSMTPPathForms(t *testing.T) {
	for _, path := range []string{
		"<bob@relay.example>", "<\"quoted local\"@relay.example>", "<café@bücher.example>",
		"<@relay.example,@other.example:bob@relay.example>", "<Postmaster>",
		"<bob@[192.0.2.1]>", "<bob@[IPv6:2001:db8::1]>", "<bob@[x-example:address]>",
	} {
		if !validDKIM2StoredEnvelope(dkim2.Envelope{MailFrom: "<>", RcptTo: []string{path}}) {
			t.Errorf("valid SMTP recipient rejected: %s", path)
		}
	}
	for _, path := range []string{"<>", "<not-a-mailbox>", "<bob@invalid_domain>", "<two words@relay.example>", "<(comment)bob@relay.example>", "<\"bob\"(comment)@relay.example>", "<\"tab\tlocal\"@relay.example>", "bob@relay.example"} {
		if validDKIM2StoredEnvelope(dkim2.Envelope{MailFrom: "<>", RcptTo: []string{path}}) {
			t.Errorf("invalid SMTP recipient accepted: %s", path)
		}
	}
}
