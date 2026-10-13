package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"banhammer/internal/model"
)

func sampleEvents(t *testing.T) []model.BanEvent {
	t.Helper()
	at := time.Date(2024, 2, 29, 23, 59, 58, 123456789, time.FixedZone("IST", 2*3600))
	return []model.BanEvent{
		{IP: mustAddr(t, "1.2.3.4"), Monitor: "sshd", At: at},
		{IP: mustAddr(t, "2001:db8::dead:beef"), Monitor: "nginx", At: at.Add(time.Hour).UTC()},
		{IP: mustAddr(t, "5.6.7.8"), Monitor: "", At: at.Add(2 * time.Hour)},
	}
}

func TestLoadHistoryMissingFile(t *testing.T) {
	t.Parallel()
	s, _, _, _ := newTestStore(t, t.TempDir())
	events, err := s.LoadHistory()
	if err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("LoadHistory = %v, want none on first run", events)
	}
}

func TestSaveLoadHistoryRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, _, _, _ := newTestStore(t, dir)
	want := sampleEvents(t)
	if err := s.SaveHistory(want); err != nil {
		t.Fatalf("SaveHistory: %v", err)
	}
	got, err := s.LoadHistory()
	if err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("LoadHistory returned %d events, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].IP != want[i].IP || got[i].Monitor != want[i].Monitor || !got[i].At.Equal(want[i].At) {
			t.Errorf("event %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// The file is one of ours: versioned, indented, newline-terminated.
	data, err := os.ReadFile(filepath.Join(dir, HistoryFile))
	if err != nil {
		t.Fatalf("read %s: %v", HistoryFile, err)
	}
	if !strings.HasPrefix(string(data), "{\n  \"version\": 1,") || !strings.HasSuffix(string(data), "\n") {
		t.Errorf("%s is not in the house format:\n%s", HistoryFile, data)
	}
}

func TestSaveHistoryEmptyEncodesAsList(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, _, _, _ := newTestStore(t, dir)
	if err := s.SaveHistory(nil); err != nil {
		t.Fatalf("SaveHistory(nil): %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, HistoryFile))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), `"events": []`) {
		t.Errorf("empty ledger must encode as [], got:\n%s", data)
	}
	got, err := s.LoadHistory()
	if err != nil || len(got) != 0 {
		t.Fatalf("LoadHistory = %v, %v; want empty, nil", got, err)
	}
}

// TestHistoryValidationIsSymmetric pins that an entry the loader refuses is
// also refused by the saver, so a bad event cannot survive one run and vanish
// on the next.
func TestHistoryValidationIsSymmetric(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, _, _, _ := newTestStore(t, dir)
	good := sampleEvents(t)[0]
	bad := []model.BanEvent{
		{Monitor: "no-ip", At: good.At},   // invalid address
		{IP: good.IP, Monitor: "no-time"}, // zero timestamp
		good,
	}
	if err := s.SaveHistory(bad); err != nil {
		t.Fatalf("SaveHistory: %v", err)
	}
	got, err := s.LoadHistory()
	if err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}
	if len(got) != 1 || got[0].IP != good.IP {
		t.Fatalf("LoadHistory = %v, want only the valid event", got)
	}

	// The same junk written by hand is dropped on load too.
	raw := `{"version":1,"events":[{"ip":"","monitor":"x","at":"2024-01-01T00:00:00Z"},{"ip":"9.9.9.9","monitor":"y","at":"0001-01-01T00:00:00Z"},{"ip":"9.9.9.9","monitor":"y","at":"2024-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(dir, HistoryFile), []byte(raw), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err = s.LoadHistory()
	if err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}
	if len(got) != 1 || got[0].Monitor != "y" {
		t.Fatalf("LoadHistory = %v, want only the valid hand-written event", got)
	}
}

func TestCorruptHistoryFileIsQuarantined(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, content string }{
		{"empty", ""},
		{"garbage", "\x00\xffnot json"},
		{"wrong version", `{"version":7,"events":[]}`},
		{"wrong shape", `[]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, HistoryFile), []byte(tc.content), 0o644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			s, _, _, _ := newTestStore(t, dir)
			events, err := s.LoadHistory()
			if err != nil {
				t.Fatalf("LoadHistory on a corrupt file must not fail: %v", err)
			}
			if len(events) != 0 {
				t.Fatalf("LoadHistory = %v, want empty state", events)
			}
			assertQuarantined(t, dir, HistoryFile, tc.content)

			// And the daemon carries on.
			if err := s.SaveHistory(sampleEvents(t)); err != nil {
				t.Fatalf("SaveHistory after corruption: %v", err)
			}
			if got, err := s.LoadHistory(); err != nil || len(got) != 3 {
				t.Fatalf("LoadHistory after recovery = %v, %v", got, err)
			}
		})
	}
}

func TestHistoryAfterClose(t *testing.T) {
	t.Parallel()
	s, _, _, _ := newTestStore(t, t.TempDir())
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.SaveHistory(nil); !errors.Is(err, ErrClosed) {
		t.Errorf("SaveHistory after Close = %v, want ErrClosed", err)
	}
	if _, err := s.LoadHistory(); !errors.Is(err, ErrClosed) {
		t.Errorf("LoadHistory after Close = %v, want ErrClosed", err)
	}
}

func TestSaveHistoryFailurePropagates(t *testing.T) {
	t.Parallel()
	s, _, _, rec := newTestStore(t, t.TempDir())
	rec.setFail(errors.New("disk full"))
	err := s.SaveHistory(sampleEvents(t))
	if err == nil || !errors.Is(err, ErrNotPersisted) {
		t.Fatalf("SaveHistory under a failing disk = %v, want ErrNotPersisted", err)
	}
}

// TestHistoryTempFilesAreSwept extends the interrupted-write sweep to the
// ledger: a crash mid-write must not leave debris that accumulates forever.
func TestHistoryTempFilesAreSwept(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	debris := filepath.Join(dir, HistoryFile+tempPrefix+"123456")
	if err := os.WriteFile(debris, []byte("partial"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	newTestStore(t, dir)
	if _, err := os.Stat(debris); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temp file %s survived Open (err=%v)", debris, err)
	}
}
