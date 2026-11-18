package arcmilter

import (
	"log"
	"sync"
	"time"

	"github.com/masa23/arcmilter/config"
)

// One worker belongs to the receive server, not to individual SMTP sessions.
// Expired originals are reclaimed even when no new mail arrives.
func startDKIM2CacheGC(conf *config.Config) func() {
	if conf.DKIM2Forwarding.Mode != "receive" {
		return func() {}
	}
	return startDKIM2CacheGCWorker(conf.DKIM2Forwarding, time.Minute, cleanupExpiredDKIM2ForwardContexts)
}

func startDKIM2CacheGCWorker(options config.DKIM2ForwardingConfig, interval time.Duration, cleanup func(config.DKIM2ForwardingConfig, int64) error) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := cleanup(options, time.Now().Unix()); err != nil {
				log.Printf("arcmilter: DKIM2 cache cleanup: %v", err)
			}
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
		}
	}()
	return func() {
		once.Do(func() { close(stop) })
		<-done
	}
}
