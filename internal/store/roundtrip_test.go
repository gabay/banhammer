package store

import (
	"encoding/json"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"banhammer/internal/model"
)

// banFileShape mirrors the on-disk envelope so the round-trip property can be
// checked without touching the filesystem.
type banFileShape struct {
	Version int         `json:"version"`
	Bans    []model.Ban `json:"bans"`
}

func randomAddr(r *rand.Rand) netip.Addr {
	switch r.IntN(5) {
	case 0:
		return netip.AddrFrom4([4]byte{byte(r.UintN(256)), byte(r.UintN(256)), byte(r.UintN(256)), byte(r.UintN(256))})
	case 1:
		var b [16]byte
		for i := range b {
			b[i] = byte(r.UintN(256))
		}
		return netip.AddrFrom16(b)
	case 2: // v4-in-v6: must survive as such, it is a distinct Addr
		var b [16]byte
		b[10], b[11] = 0xff, 0xff
		b[12], b[13], b[14], b[15] = byte(r.UintN(256)), byte(r.UintN(256)), byte(r.UintN(256)), byte(r.UintN(256))
		return netip.AddrFrom16(b)
	case 3: // link-local with a zone
		var b [16]byte
		b[0], b[1] = 0xfe, 0x80
		b[15] = byte(1 + r.UintN(255))
		return netip.AddrFrom16(b).WithZone("eth0")
	default:
		return netip.AddrFrom4([4]byte{10, byte(r.UintN(256)), byte(r.UintN(256)), 1})
	}
}

func randomTime(r *rand.Rand) time.Time {
	loc := time.UTC
	switch r.IntN(4) {
	case 1:
		// Quarter-hour offsets are the only ones RFC3339 can express faithfully.
		loc = time.FixedZone("ZZZ", (r.IntN(105)-48)*15*60)
	case 2:
		loc = time.Local
	}
	base := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	return base.Add(time.Duration(r.Int64N(int64(200_000 * time.Hour)))).In(loc)
}

// TestBanJSONRoundTripProperty checks the two encodings that actually bite:
// netip.Addr (v4, v6, v4-in-v6, zoned) and time.Time (zone offset preserved).
func TestBanJSONRoundTripProperty(t *testing.T) {
	t.Parallel()
	seed1, seed2 := uint64(0x9E3779B97F4A7C15), uint64(0xBF58476D1CE4E5B9)
	r := rand.New(rand.NewPCG(seed1, seed2))

	for i := 0; i < 500; i++ {
		want := model.Ban{
			IP:      randomAddr(r),
			Monitor: []string{"sshd", "nginx", "", "postfix-submission"}[r.IntN(4)],
			At:      randomTime(r),
			Count:   r.IntN(1 << 20),
			Offense: r.IntN(64),
		}
		want.Until = want.At.Add(time.Duration(r.Int64N(int64(720 * time.Hour))))

		data, err := marshalState(banFileShape{Version: stateVersion, Bans: []model.Ban{want}})
		if err != nil {
			t.Fatalf("seed %d/%d iteration %d: marshal %+v: %v", seed1, seed2, i, want, err)
		}
		var back banFileShape
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("iteration %d: unmarshal %s: %v", i, data, err)
		}
		if len(back.Bans) != 1 {
			t.Fatalf("iteration %d: got %d bans", i, len(back.Bans))
		}
		got := back.Bans[0]

		if got.IP != want.IP {
			t.Fatalf("iteration %d: IP %v -> %v (json %s)", i, want.IP, got.IP, data)
		}
		if got.IP.Is4In6() != want.IP.Is4In6() {
			t.Fatalf("iteration %d: v4-in-v6 flag lost for %v", i, want.IP)
		}
		if got.IP.Zone() != want.IP.Zone() {
			t.Fatalf("iteration %d: zone %q -> %q", i, want.IP.Zone(), got.IP.Zone())
		}
		assertTimeEqual(t, "At", got.At, want.At)
		assertTimeEqual(t, "Until", got.Until, want.Until)
		if got.Monitor != want.Monitor || got.Count != want.Count || got.Offense != want.Offense {
			t.Fatalf("iteration %d: %+v != %+v", i, got, want)
		}
	}
}

func TestCheckpointJSONRoundTripProperty(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 200; i++ {
		want := map[string]model.Checkpoint{}
		for j := 0; j < r.IntN(5)+1; j++ {
			cp := model.Checkpoint{
				Path:   filepath.Join("/var/log", string(rune('a'+r.IntN(26)))+".log"),
				Dev:    r.Uint64(),
				Inode:  r.Uint64(),
				Offset: r.Int64(),
			}
			want[cp.Path] = cp
		}
		data, err := marshalState(struct {
			Version int                         `json:"version"`
			Offsets map[string]model.Checkpoint `json:"offsets"`
		}{Version: stateVersion, Offsets: want})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var back struct {
			Version int                         `json:"version"`
			Offsets map[string]model.Checkpoint `json:"offsets"`
		}
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("unmarshal %s: %v", data, err)
		}
		if len(back.Offsets) != len(want) {
			t.Fatalf("got %d offsets, want %d", len(back.Offsets), len(want))
		}
		for k, w := range want {
			// uint64 dev/inode near 2^64 are the classic JSON-number trap.
			if back.Offsets[k] != w {
				t.Fatalf("offset %q = %+v, want %+v", k, back.Offsets[k], w)
			}
		}
	}
}

// TestAddrRoundTripThroughStore pins the same guarantee end to end, through
// the real files.
func TestAddrRoundTripThroughStore(t *testing.T) {
	t.Parallel()
	addrs := []string{
		"0.0.0.0", "255.255.255.255", "1.2.3.4",
		"::", "::1", "2001:db8::1", "fe80::1%eth0",
		"::ffff:1.2.3.4", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	}
	dir := t.TempDir()
	var want []model.Ban
	at := time.Date(2031, 12, 31, 23, 59, 59, 999999999, time.FixedZone("NPT", 5*3600+45*60))
	for i, a := range addrs {
		want = append(want, model.Ban{
			IP: mustAddr(t, a), Monitor: "m", At: at, Until: at.Add(time.Duration(i) * time.Hour),
			Count: i, Offense: i%3 + 1,
		})
	}

	s, _, _, _ := newTestStore(t, dir)
	if err := s.SaveBans(want); err != nil {
		t.Fatalf("SaveBans: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	got, err := s.LoadBans()
	if err != nil {
		t.Fatalf("LoadBans: %v", err)
	}
	assertBansEqual(t, got, want)
	for i := range want {
		if got[i].IP.Is4In6() != want[i].IP.Is4In6() {
			t.Errorf("%v: v4-in-v6 flag lost", want[i].IP)
		}
		if got[i].Family() != want[i].Family() {
			t.Errorf("%v: family changed", want[i].IP)
		}
	}
}

// FuzzStateFiles asserts the central robustness property: whatever bytes are
// on disk, the store starts, never panics, and never reports the state files
// as a fatal error. The two files get their own input because they are read on
// different paths — offsets.json inside Open, bans.json on demand — and the
// interesting cases are the mixed ones: a good file next to a broken one.
func FuzzStateFiles(f *testing.F) {
	corpus := []string{
		"",
		"{",
		`{"version":1,"bans":[{"ip":"1.2.3.4"`,
		`{"version":1,"bans":[{"ip":"nonsense","at":"not-a-time"}]}`,
		`{"version":1,"bans":[{"ip":"1.2.3.4","at":"2024-01-02T00:00:00Z","until":"2024-01-01T00:00:00Z"}]}`,
		`{"version":1,"offsets":{"/a":{"path":"/a","offset":-1}}}`,
		`{"version":1,"offsets":{"/a":{"path":"/a","offset":1},"b":{"path":"/a","offset":2}}}`,
		`{"version":99,"bans":[]}`,
		"\x00\x01\x02\xff",
	}
	for i, bans := range corpus {
		// Pair every input with itself and with the next one, so the seeds
		// cover both files being broken and only one of them.
		f.Add([]byte(bans), []byte(bans))
		f.Add([]byte(bans), []byte(corpus[(i+1)%len(corpus)]))
	}

	f.Fuzz(func(t *testing.T, bansData, offsetsData []byte) {
		dir := t.TempDir()
		for name, data := range map[string][]byte{BansFile: bansData, OffsetsFile: offsetsData} {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
				t.Fatalf("seed %s: %v", name, err)
			}
		}
		s, err := OpenWith(dir, Options{Log: discardLogger()})
		if err != nil {
			t.Fatalf("Open must tolerate any offsets.json content: %v", err)
		}
		defer s.Close() //nolint:errcheck // nothing pending

		bans, err := s.LoadBans()
		if err != nil {
			t.Fatalf("LoadBans must tolerate any content: %v", err)
		}
		for _, b := range bans {
			if !b.IP.IsValid() {
				t.Fatalf("LoadBans returned an invalid address: %+v", b)
			}
			if b.Until.Before(b.At) {
				t.Fatalf("LoadBans returned a ban that expires before it started: %+v", b)
			}
		}
		offsets, err := s.LoadOffsets()
		if err != nil {
			t.Fatalf("LoadOffsets: %v", err)
		}
		for k, cp := range offsets {
			if cp.Offset < 0 {
				t.Fatalf("LoadOffsets returned a negative offset for %q: %+v", k, cp)
			}
		}
		s.Lookup("/var/log/auth.log")

		// Whatever happened, the store must still be writable.
		if err := s.SaveBans(bans); err != nil {
			t.Fatalf("SaveBans: %v", err)
		}
		if err := s.SaveOffsets(offsets); err != nil {
			t.Fatalf("SaveOffsets: %v", err)
		}
		if err := s.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
	})
}
