package test

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"banhammer/internal/config"
	"banhammer/internal/daemon"
	"banhammer/internal/rule"
	"banhammer/internal/window"
)

const corpusSize = 1_000_000

var (
	authCorpusOnce sync.Once
	authCorpus     [][]byte

	jsonCorpusOnce sync.Once
	jsonCorpus     [][]byte

	nonMatchingAuthLines = [][]byte{
		[]byte("Sep 15 10:00:01 web01 CRON[10234]: (root) CMD (/usr/local/bin/backup-sync.sh > /dev/null 2>&1)"),
		[]byte("Sep 15 10:00:02 web01 sshd[10235]: Accepted publickey for deploy from 192.168.1.50 port 45123 ssh2: RSA SHA256:abcd1234efgh5678"),
		[]byte("Sep 15 10:00:03 web01 sshd[10235]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)"),
		[]byte("Sep 15 10:00:04 web01 sshd[10235]: Received disconnect from 192.168.1.50 port 45123:11: disconnected by user"),
		[]byte("Sep 15 10:00:05 web01 systemd[1]: Starting Rotate log files..."),
		[]byte("Sep 15 10:00:06 web01 systemd[1]: logrotate.service: Deactivated successfully."),
		[]byte("Sep 15 10:00:07 web01 sudo:   roigabay : TTY=pts/0 ; PWD=/home/roigabay ; USER=root ; COMMAND=/bin/journalctl -u sshd"),
		[]byte("Sep 15 10:00:08 web01 kernel: [98765.432100] audit: type=1101 audit(1694780000.123:456): pid=12345 uid=1000 auid=1000"),
		[]byte("Sep 15 10:00:09 web01 sshd[10239]: pam_unix(sshd:session): session closed for user deploy"),
		[]byte("Sep 15 10:00:10 web01 CRON[10240]: (daemon) CMD (test -x /usr/lib/php/sessionclean && /usr/lib/php/sessionclean)"),
	}

	matchingAuthLines = [][]byte{
		[]byte("Sep 15 10:01:00 web01 sshd[1101]: Failed password for invalid user admin from 198.51.100.23 port 41234 ssh2"),
		[]byte("Sep 15 10:01:01 web01 sshd[1102]: Failed password for root from 203.0.113.88 port 59123 ssh2"),
		[]byte("Sep 15 10:01:02 web01 sshd[1103]: Invalid user guest from 198.51.100.24 port 38291"),
		[]byte("Sep 15 10:01:03 web01 sshd[1104]: Failed password for ubuntu from 198.51.100.25 port 44102 ssh2"),
	}

	nonMatchingJSONLines = [][]byte{
		[]byte(`{"time":"2026-09-15T10:00:00Z","request":{"remote_ip":"192.0.2.1","method":"GET","uri":"/index.html"},"status":200,"bytes":1542}`),
		[]byte(`{"time":"2026-09-15T10:00:01Z","request":{"remote_ip":"192.0.2.2","method":"GET","uri":"/assets/main.css"},"status":200,"bytes":8421}`),
		[]byte(`{"time":"2026-09-15T10:00:02Z","request":{"remote_ip":"192.0.2.3","method":"GET","uri":"/assets/bundle.js"},"status":200,"bytes":48201}`),
		[]byte(`{"time":"2026-09-15T10:00:03Z","request":{"remote_ip":"192.0.2.4","method":"POST","uri":"/api/v1/telemetry"},"status":204,"bytes":0}`),
		[]byte(`{"time":"2026-09-15T10:00:04Z","request":{"remote_ip":"192.0.2.5","method":"GET","uri":"/favicon.ico"},"status":200,"bytes":318}`),
		[]byte(`{"time":"2026-09-15T10:00:05Z","request":{"remote_ip":"192.0.2.6","method":"GET","uri":"/images/banner.webp"},"status":200,"bytes":32941}`),
		[]byte(`{"time":"2026-09-15T10:00:06Z","request":{"remote_ip":"192.0.2.7","method":"GET","uri":"/about"},"status":200,"bytes":2410}`),
		[]byte(`{"time":"2026-09-15T10:00:07Z","request":{"remote_ip":"192.0.2.8","method":"GET","uri":"/docs/intro"},"status":200,"bytes":9411}`),
	}

	matchingJSONLines = [][]byte{
		[]byte(`{"time":"2026-09-15T10:01:00Z","request":{"remote_ip":"198.51.100.101","method":"GET","uri":"/.env"},"status":404,"bytes":162}`),
		[]byte(`{"time":"2026-09-15T10:01:01Z","request":{"remote_ip":"198.51.100.102","method":"GET","uri":"/wp-login.php"},"status":401,"bytes":210}`),
		[]byte(`{"time":"2026-09-15T10:01:02Z","request":{"remote_ip":"198.51.100.103","method":"GET","uri":"/.git/config"},"status":403,"bytes":180}`),
		[]byte(`{"time":"2026-09-15T10:01:03Z","request":{"remote_ip":"198.51.100.104","method":"GET","uri":"/admin/config.ini"},"status":404,"bytes":162}`),
	}
)

func getAuthCorpus() [][]byte {
	authCorpusOnce.Do(func() {
		authCorpus = make([][]byte, corpusSize)
		// 98% non-matching, 2% attacks spread across various IPs
		for i := 0; i < corpusSize; i++ {
			if i%50 == 0 {
				ip := fmt.Sprintf("198.51.%d.%d", (i/256)%250+1, i%254+1)
				authCorpus[i] = []byte(fmt.Sprintf("Sep 15 10:01:00 web01 sshd[%d]: Failed password for invalid user admin from %s port 41234 ssh2", 10000+i%20000, ip))
			} else {
				authCorpus[i] = nonMatchingAuthLines[i%len(nonMatchingAuthLines)]
			}
		}
	})
	return authCorpus
}

func getJSONCorpus() [][]byte {
	jsonCorpusOnce.Do(func() {
		jsonCorpus = make([][]byte, corpusSize)
		// 98% non-matching, 2% attacks spread across various IPs
		for i := 0; i < corpusSize; i++ {
			if i%50 == 0 {
				ip := fmt.Sprintf("203.0.%d.%d", (i/256)%250+1, i%254+1)
				uri := "/.env"
				if i%100 == 0 {
					uri = "/wp-login.php"
				}
				jsonCorpus[i] = []byte(fmt.Sprintf(`{"time":"2026-09-15T10:01:00Z","request":{"remote_ip":"%s","method":"GET","uri":"%s"},"status":404,"bytes":162}`, ip, uri))
			} else {
				jsonCorpus[i] = nonMatchingJSONLines[i%len(nonMatchingJSONLines)]
			}
		}
	})
	return jsonCorpus
}

func compileAuthRuleSet() *rule.Set {
	set, err := rule.Compile(rule.Spec{
		Format: "text",
		Line: []string{
			"Failed password .* from <IP>",
			"Invalid user .* from <IP>",
		},
	})
	if err != nil {
		panic(err)
	}
	return set
}

func compileJSONRuleSet() *rule.Set {
	set, err := rule.Compile(rule.Spec{
		Format: "json",
		Fields: map[string]string{
			"status":      "^(401|403|404)$",
			"request.uri": "\\.(env|git|ini|php)$",
		},
		IPField: "request.remote_ip",
	})
	if err != nil {
		panic(err)
	}
	return set
}

type recordingRunner struct {
	mu    sync.Mutex
	calls [][]string
}

func (r *recordingRunner) Run(ctx context.Context, argv []string, shell bool) ([]byte, error) {
	r.mu.Lock()
	r.calls = append(r.calls, slices.Clone(argv))
	r.mu.Unlock()
	return nil, nil
}

func (r *recordingRunner) HasArg(arg string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, call := range r.calls {
		if slices.Contains(call, arg) {
			return true
		}
	}
	return false
}

// TestPipeline_EndToEnd_AuthLog tests full daemon ingestion, matching, and ban
// evaluation on synthetic auth.log data.
func TestPipeline_EndToEnd_AuthLog(t *testing.T) {
	stateDir := t.TempDir()
	cfg := &config.Config{
		StateDir:   stateDir,
		LogFormat:  "text",
		AllowLocal: true,
		Allowlist:  []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		QueueSize:  16384,
		Defaults: config.Settings{
			Threshold:     5,
			Window:        10 * time.Minute,
			Bantime:       1 * time.Hour,
			BantimeFactor: 1,
			BantimeMax:    24 * time.Hour,
			FindHistory:   24 * time.Hour,
			MaxTracked:    10000,
			StartAt:       "beginning",
			OnRepeat:      "ignore",
			Action: config.ActionSpec{
				Name:    "iptables",
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
					MaxTracked:    10000,
					StartAt:       "beginning",
					OnRepeat:      "ignore",
					Action: config.ActionSpec{
						Name:    "iptables",
						Timeout: 5 * time.Second,
					},
				},
			},
		},
	}

	runner := &recordingRunner{}
	var inputBuf bytes.Buffer

	// Write 200 benign lines
	for i := 0; i < 200; i++ {
		inputBuf.Write(nonMatchingAuthLines[i%len(nonMatchingAuthLines)])
		inputBuf.WriteByte('\n')
	}
	// Write 6 failed attempts for attacker 198.51.100.77 (crosses threshold 5)
	for i := 0; i < 6; i++ {
		inputBuf.WriteString(fmt.Sprintf("Sep 15 10:02:0%d web01 sshd[222%d]: Failed password for invalid user admin from 198.51.100.77 port 3312%d ssh2\n", i, i, i))
	}
	// Write 6 failed attempts for allowlisted IP 127.0.0.1 (should NOT be banned)
	for i := 0; i < 6; i++ {
		inputBuf.WriteString(fmt.Sprintf("Sep 15 10:02:1%d web01 sshd[223%d]: Failed password for invalid user admin from 127.0.0.1 port 3313%d ssh2\n", i, i, i))
	}
	// Write 200 more benign lines
	for i := 0; i < 200; i++ {
		inputBuf.Write(nonMatchingAuthLines[i%len(nonMatchingAuthLines)])
		inputBuf.WriteByte('\n')
	}

	d, err := daemon.New(cfg,
		daemon.WithRunner(runner),
		daemon.WithStdin(&inputBuf),
		daemon.WithControlSocket(""),
	)
	if err != nil {
		t.Fatalf("daemon.New failed: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- d.Run(ctx)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runner.HasArg("198.51.100.77") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !runner.HasArg("198.51.100.77") {
		t.Fatalf("expected attacker 198.51.100.77 to be banned by runner")
	}
	if runner.HasArg("127.0.0.1") {
		t.Fatalf("allowlisted IP 127.0.0.1 must NOT be banned")
	}

	cancel()
	_ = <-runErrCh
}

// TestPipeline_EndToEnd_JSON tests full daemon ingestion and matching on JSON logs.
func TestPipeline_EndToEnd_JSON(t *testing.T) {
	stateDir := t.TempDir()
	cfg := &config.Config{
		StateDir:   stateDir,
		LogFormat:  "text",
		AllowLocal: true,
		QueueSize:  16384,
		Defaults: config.Settings{
			Threshold:     5,
			Window:        10 * time.Minute,
			Bantime:       1 * time.Hour,
			BantimeFactor: 1,
			BantimeMax:    24 * time.Hour,
			FindHistory:   24 * time.Hour,
			MaxTracked:    10000,
			StartAt:       "beginning",
			OnRepeat:      "ignore",
			Action: config.ActionSpec{
				Name:    "iptables",
				Timeout: 5 * time.Second,
			},
		},
		Monitors: map[string]*config.Monitor{
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
					Threshold:     5,
					Window:        10 * time.Minute,
					Bantime:       1 * time.Hour,
					BantimeFactor: 1,
					BantimeMax:    24 * time.Hour,
					FindHistory:   24 * time.Hour,
					MaxTracked:    10000,
					StartAt:       "beginning",
					OnRepeat:      "ignore",
					Action: config.ActionSpec{
						Name:    "iptables",
						Timeout: 5 * time.Second,
					},
				},
			},
		},
	}

	runner := &recordingRunner{}
	var inputBuf bytes.Buffer

	// Write 100 benign JSON lines
	for i := 0; i < 100; i++ {
		inputBuf.Write(nonMatchingJSONLines[i%len(nonMatchingJSONLines)])
		inputBuf.WriteByte('\n')
	}
	// Write 6 offending requests for 203.0.113.99
	for i := 0; i < 6; i++ {
		inputBuf.WriteString(fmt.Sprintf(`{"time":"2026-09-15T10:02:0%dZ","request":{"remote_ip":"203.0.113.99","method":"GET","uri":"/.env"},"status":404,"bytes":162}`+"\n", i))
	}
	// Write 100 more benign lines
	for i := 0; i < 100; i++ {
		inputBuf.Write(nonMatchingJSONLines[i%len(nonMatchingJSONLines)])
		inputBuf.WriteByte('\n')
	}

	d, err := daemon.New(cfg,
		daemon.WithRunner(runner),
		daemon.WithStdin(&inputBuf),
		daemon.WithControlSocket(""),
	)
	if err != nil {
		t.Fatalf("daemon.New failed: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- d.Run(ctx)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runner.HasArg("203.0.113.99") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !runner.HasArg("203.0.113.99") {
		t.Fatalf("expected attacker 203.0.113.99 to be banned by runner")
	}

	cancel()
	if err := <-runErrCh; err != nil {
		t.Errorf("daemon Run returned %v, want nil after cancellation", err)
	}
}

// TestPipeline_Allocations_NonMatching verifies the PROJECT.md §7 guarantee:
// allocations per line must be 0 on the non-matching path.
func TestPipeline_Allocations_NonMatching(t *testing.T) {
	if raceEnabled {
		t.Skip("race instrumentation adds its own allocations; see race_test.go")
	}

	authSet := compileAuthRuleSet()
	jsonSet := compileJSONRuleSet()

	for i, line := range nonMatchingAuthLines {
		allocs := testing.AllocsPerRun(100, func() {
			_, out := authSet.Match(line)
			if out != rule.OutcomeNoMatch {
				t.Fatalf("unexpected outcome: %v", out)
			}
		})
		if allocs > 0 {
			t.Errorf("auth.log non-matching line %d allocated %f allocs/op, want 0", i, allocs)
		}
	}

	for i, line := range nonMatchingJSONLines {
		allocs := testing.AllocsPerRun(100, func() {
			_, out := jsonSet.Match(line)
			if out != rule.OutcomeNoMatch {
				t.Fatalf("unexpected outcome: %v", out)
			}
		})
		if allocs > 0 {
			t.Errorf("json non-matching line %d allocated %f allocs/op, want 0", i, allocs)
		}
	}
}

// BenchmarkPipeline measures pipeline throughput (lines/sec and B/op) across
// 1M-line synthetic auth.log and JSON corpora per PROJECT.md §7.
func BenchmarkPipeline(b *testing.B) {
	authCorpus := getAuthCorpus()
	jsonCorpus := getJSONCorpus()
	authSet := compileAuthRuleSet()
	jsonSet := compileJSONRuleSet()

	clockNow := time.Now()
	nowFn := func() time.Time { return clockNow }
	authTracker := window.New(5, 10*time.Minute, 100_000, nowFn)
	jsonTracker := window.New(20, 1*time.Minute, 100_000, nowFn)

	b.Run("AuthLog/1M_Corpus", func(b *testing.B) {
		benchmarkPipelineCorpus(b, authCorpus, authSet, authTracker)
	})

	b.Run("AuthLog/NonMatching", func(b *testing.B) {
		benchmarkPipelineCorpus(b, nonMatchingAuthLines, authSet, authTracker)
	})

	b.Run("AuthLog/Matching", func(b *testing.B) {
		benchmarkPipelineCorpus(b, matchingAuthLines, authSet, authTracker)
	})

	b.Run("JSON/1M_Corpus", func(b *testing.B) {
		benchmarkPipelineCorpus(b, jsonCorpus, jsonSet, jsonTracker)
	})

	b.Run("JSON/NonMatching", func(b *testing.B) {
		benchmarkPipelineCorpus(b, nonMatchingJSONLines, jsonSet, jsonTracker)
	})

	b.Run("JSON/Matching", func(b *testing.B) {
		benchmarkPipelineCorpus(b, matchingJSONLines, jsonSet, jsonTracker)
	})
}

func benchmarkPipelineCorpus(b *testing.B, corpus [][]byte, set *rule.Set, tracker *window.Tracker) {
	nLines := len(corpus)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		line := corpus[i%nLines]
		res, outcome := set.Match(line)
		if outcome == rule.OutcomeMatch {
			tracker.Hit(res.IP)
		}
	}

	// b.Elapsed rather than a hand-rolled time.Since: it excludes the time the
	// framework paused the clock for, so the rate matches the ns/op it prints.
	if elapsed := b.Elapsed().Seconds(); elapsed > 0 {
		b.ReportMetric(float64(b.N)/elapsed, "lines/sec")
	}
}

// BenchmarkPipeline_AuthLog_1M measures throughput over the 1M-line auth.log corpus.
func BenchmarkPipeline_AuthLog_1M(b *testing.B) {
	corpus := getAuthCorpus()
	set := compileAuthRuleSet()
	tracker := window.New(5, 10*time.Minute, 100_000, time.Now)
	benchmarkPipelineCorpus(b, corpus, set, tracker)
}

// BenchmarkPipeline_JSON_1M measures throughput over the 1M-line JSON corpus.
func BenchmarkPipeline_JSON_1M(b *testing.B) {
	corpus := getJSONCorpus()
	set := compileJSONRuleSet()
	tracker := window.New(20, 1*time.Minute, 100_000, time.Now)
	benchmarkPipelineCorpus(b, corpus, set, tracker)
}
