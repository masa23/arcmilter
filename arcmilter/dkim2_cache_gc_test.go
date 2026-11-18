package arcmilter

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/masa23/arcmilter/config"
)

func TestDKIM2CacheGCExpiresOriginalWithoutAnotherSave(t *testing.T) {
	options, envelope, raw := dkim2StoreFixture(t)
	options.MaxAgeSeconds = 60
	id := saveDKIM2StoreFixture(t, options, envelope, raw)
	path := filepath.Join(options.StoreDirectory, id+".ctx")
	var now atomic.Int64
	now.Store(time.Now().Unix())
	initial := make(chan struct{}, 1)
	errors := make(chan error, 8)
	stop := startDKIM2CacheGCWorker(options, 10*time.Millisecond, func(options config.DKIM2ForwardingConfig, _ int64) error {
		err := cleanupExpiredDKIM2ForwardContexts(options, now.Load())
		if err != nil {
			select {
			case errors <- err:
			default:
			}
		}
		select {
		case initial <- struct{}{}:
		default:
		}
		return err
	})
	defer stop()
	select {
	case <-initial:
	case <-time.After(time.Second):
		t.Fatal("initial cache sweep did not run")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("unexpired original was removed: %v", err)
	}
	now.Add(61)
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-errors:
			t.Fatalf("cache sweep failed: %v", err)
		case <-deadline:
			t.Fatal("expired original remained without new SMTP traffic")
		case <-ticker.C:
			if _, err := os.Stat(path); os.IsNotExist(err) {
				return
			}
		}
	}
}

func TestDKIM2CacheGCStopsAndCanBeStoppedTwice(t *testing.T) {
	var calls atomic.Int64
	initial := make(chan struct{}, 1)
	stop := startDKIM2CacheGCWorker(config.DKIM2ForwardingConfig{}, time.Millisecond, func(config.DKIM2ForwardingConfig, int64) error {
		calls.Add(1)
		select {
		case initial <- struct{}{}:
		default:
		}
		return nil
	})
	select {
	case <-initial:
	case <-time.After(time.Second):
		t.Fatal("initial cache sweep did not run")
	}
	stop()
	stop()
	stoppedAt := calls.Load()
	time.Sleep(5 * time.Millisecond)
	if calls.Load() != stoppedAt {
		t.Fatal("cache sweep continued after server shutdown")
	}
}
