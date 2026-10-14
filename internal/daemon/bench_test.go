package daemon

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"banhammer/internal/config"
	"banhammer/internal/model"
)

var (
	benchAuthCorpusOnce sync.Once
	benchAuthCorpus     [][]byte

	benchJSONCorpusOnce sync.Once
	benchJSONCorpus     [][]byte
)

func getBenchAuthCorpus() [][]byte {
	benchAuthCorpusOnce.Do(func() {
		const total = 100_000
		benchAuthCorpus = make([][]byte, total)
		benign := []byte("Sep 15 10:00:01 web01 CRON[10234]: (root) CMD (/usr/local/bin/backup.sh)")
		for i := 0; i < total; i++ {
			if i%50 == 0 {
				benchAuthCorpus[i] = []byte(fmt.Sprintf("Sep 15 10:01:00 web01 sshd[%d]: Failed password for invalid user admin from 198.51.100.%d port 41234 ssh2", 10000+i, i%250+1))
			} else {
				benchAuthCorpus[i] = benign
			}
		}
	})
	return benchAuthCorpus
}

func getBenchJSONCorpus() [][]byte {
	benchJSONCorpusOnce.Do(func() {
		const total = 100_000
		benchJSONCorpus = make([][]byte, total)
		benign := []byte(`{"time":"2026-09-15T10:00:00Z","request":{"remote_ip":"192.0.2.1","method":"GET","uri":"/index.html"},"status":200,"bytes":1542}`)
		for i := 0; i < total; i++ {
			if i%50 == 0 {
				benchJSONCorpus[i] = []byte(fmt.Sprintf(`{"time":"2026-09-15T10:01:00Z","request":{"remote_ip":"203.0.113.%d","method":"GET","uri":"/.env"},"status":404,"bytes":162}`, i%250+1))
			} else {
				benchJSONCorpus[i] = benign
			}
		}
	})
	return benchJSONCorpus
}

func BenchmarkPipeline(b *testing.B) {
	stateDir := b.TempDir()
	cfg := &config.Config{
		StateDir:   stateDir,
		LogFormat:  "text",
		AllowLocal: true,
		QueueSize:  65536,
		Defaults: config.Settings{
			Threshold:     5,
			Window:        10 * time.Minute,
			Bantime:       1 * time.Hour,
			BantimeFactor: 1,
			BantimeMax:    24 * time.Hour,
			FindHistory:   24 * time.Hour,
			MaxTracked:    100_000,
			StartAt:       "beginning",
			OnRepeat:      "ignore",
			Action: config.ActionSpec{
				Name:    "dryrun",
				Timeout: 5 * time.Second,
			},
		},
		Monitors: map[string]*config.Monitor{
			"sshd": {
				Name:   "sshd",
				Stdin:  true,
				Format: "text",
				Match: config.Patterns{
					Line: []string{
						"Failed password .* from <IP>",
						"Invalid user .* from <IP>",
					},
				},
				Settings: config.Settings{
					Threshold:     5,
					Window:        10 * time.Minute,
					Bantime:       1 * time.Hour,
					BantimeFactor: 1,
					BantimeMax:    24 * time.Hour,
					FindHistory:   24 * time.Hour,
					MaxTracked:    100_000,
					StartAt:       "beginning",
					OnRepeat:      "ignore",
					Action: config.ActionSpec{
						Name:    "dryrun",
						Timeout: 5 * time.Second,
					},
				},
			},
			"caddy": {
				Name:    "caddy",
				Stdin:   true,
				Format:  "json",
				IPField: "request.remote_ip",
				Match: config.Patterns{
					Fields: map[string]string{
						"status":      "^(401|403|404)$",
						"request.uri": "\\.(env|git|ini|php)$",
					},
				},
				Settings: config.Settings{
					Threshold:     20,
					Window:        1 * time.Minute,
					Bantime:       1 * time.Hour,
					BantimeFactor: 1,
					BantimeMax:    24 * time.Hour,
					FindHistory:   24 * time.Hour,
					MaxTracked:    100_000,
					StartAt:       "beginning",
					OnRepeat:      "ignore",
					Action: config.ActionSpec{
						Name:    "dryrun",
						Timeout: 5 * time.Second,
					},
				},
			},
		},
	}

	d, err := New(cfg, WithControlSocket(""))
	if err != nil {
		b.Fatalf("daemon.New failed: %v", err)
	}
	defer d.Close()

	stopCh := make(chan struct{})
	go func() {
		for {
			select {
			case <-d.matchCh:
			case <-stopCh:
				return
			}
		}
	}()
	defer close(stopCh)

	authCorpus := getBenchAuthCorpus()
	jsonCorpus := getBenchJSONCorpus()
	var arena lineArena

	b.Run("Daemon_ProcessEvent_AuthLog", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		start := time.Now()
		n := len(authCorpus)
		for i := 0; i < b.N; i++ {
			ev := model.Event{
				Monitor: "sshd",
				Raw:     authCorpus[i%n],
				Recv:    start,
			}
			d.processEvent(ev, &arena)
		}
		elapsed := time.Since(start).Seconds()
		if elapsed > 0 {
			b.ReportMetric(float64(b.N)/elapsed, "lines/sec")
		}
	})

	b.Run("Daemon_ProcessEvent_JSON", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		start := time.Now()
		n := len(jsonCorpus)
		for i := 0; i < b.N; i++ {
			ev := model.Event{
				Monitor: "caddy",
				Raw:     jsonCorpus[i%n],
				Recv:    start,
			}
			d.processEvent(ev, &arena)
		}
		elapsed := time.Since(start).Seconds()
		if elapsed > 0 {
			b.ReportMetric(float64(b.N)/elapsed, "lines/sec")
		}
	})

	// The same auth.log path with offending-line capture on, which is the
	// shipped default: the per-match copy must stay amortised to roughly
	// nothing (one allocation per 64 KiB of matched text).
	b.Run("Daemon_ProcessEvent_AuthLog_CaptureLines", func(b *testing.B) {
		d.captureLines.Store(true)
		defer d.captureLines.Store(false)
		b.ReportAllocs()
		b.ResetTimer()
		start := time.Now()
		n := len(authCorpus)
		for i := 0; i < b.N; i++ {
			ev := model.Event{
				Monitor: "sshd",
				Raw:     authCorpus[i%n],
				Recv:    start,
			}
			d.processEvent(ev, &arena)
		}
		elapsed := time.Since(start).Seconds()
		if elapsed > 0 {
			b.ReportMetric(float64(b.N)/elapsed, "lines/sec")
		}
	})
}
