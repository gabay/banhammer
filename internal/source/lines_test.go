package source

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestSplitterPush(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		max    int
		chunks []string
		want   []string
		// wantPending is the carry left over after the last chunk.
		wantPending int
		wantTrunc   uint64
	}{
		{
			name:   "whole lines in one chunk",
			chunks: []string{"a\nb\nc\n"},
			want:   []string{"a", "b", "c"},
		},
		{
			name:        "trailing partial is withheld",
			chunks:      []string{"a\npart"},
			want:        []string{"a"},
			wantPending: 4,
		},
		{
			name:   "partial completed by the next chunk",
			chunks: []string{"pa", "rt", "ial\n"},
			want:   []string{"partial"},
		},
		{
			name:   "byte at a time",
			chunks: []string{"h", "i", "\n", "y", "o", "\n"},
			want:   []string{"hi", "yo"},
		},
		{
			name:   "crlf is trimmed",
			chunks: []string{"a\r\nb\r\n"},
			want:   []string{"a", "b"},
		},
		{
			name:   "empty lines are preserved by the splitter",
			chunks: []string{"\n\na\n"},
			want:   []string{"", "", "a"},
		},
		{
			name:      "over-long line truncated then the next line survives",
			max:       4,
			chunks:    []string{"aaaaaaaaaa\nbb\n"},
			want:      []string{"aaaa", "bb"},
			wantTrunc: 1,
		},
		{
			name:      "over-long line spanning chunks",
			max:       4,
			chunks:    []string{"aaa", "aaa", "aa", "\nbb\n"},
			want:      []string{"aaaa", "bb"},
			wantTrunc: 1,
		},
		{
			name:      "line exactly at the limit is not truncated",
			max:       4,
			chunks:    []string{"abcd\n"},
			want:      []string{"abcd"},
			wantTrunc: 0,
		},
		{
			// The no-newline path used to truncate at >= max, so this line
			// was reported truncated and its newline was swallowed as the
			// start of the discarded tail — taking "bb" with it.
			name:      "line exactly at the limit split across chunks",
			max:       4,
			chunks:    []string{"abcd", "\nbb\n"},
			want:      []string{"abcd", "bb"},
			wantTrunc: 0,
		},
		{
			name:      "one byte over the limit is truncated",
			max:       4,
			chunks:    []string{"abcde", "\nbb\n"},
			want:      []string{"abcd", "bb"},
			wantTrunc: 1,
		},
		{
			name:   "no data",
			chunks: []string{""},
			want:   nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sp := splitter{max: tc.max}
			var got []string
			emit := func(line []byte) error {
				got = append(got, string(line))
				return nil
			}
			for _, c := range tc.chunks {
				if err := sp.push([]byte(c), emit); err != nil {
					t.Fatalf("push(%q) = %v", c, err)
				}
			}
			if !equalStrings(got, tc.want) {
				t.Errorf("lines = %q, want %q", got, tc.want)
			}
			if sp.pending() != tc.wantPending {
				t.Errorf("pending = %d, want %d", sp.pending(), tc.wantPending)
			}
			if sp.truncated != tc.wantTrunc {
				t.Errorf("truncated = %d, want %d", sp.truncated, tc.wantTrunc)
			}
		})
	}
}

// A line exactly at the limit must not be truncated, and the limit must apply
// to a line assembled from a carry plus a chunk, not just to one chunk.
func TestSplitterLimitAcrossCarry(t *testing.T) {
	t.Parallel()
	sp := splitter{max: 8}
	var got []string
	emit := func(line []byte) error { got = append(got, string(line)); return nil }
	if err := sp.push([]byte("1234"), emit); err != nil {
		t.Fatal(err)
	}
	if err := sp.push([]byte("56789\n"), emit); err != nil {
		t.Fatal(err)
	}
	if want := []string{"12345678"}; !equalStrings(got, want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
	if sp.truncated != 1 {
		t.Fatalf("truncated = %d, want 1", sp.truncated)
	}
}

func TestSplitterFlush(t *testing.T) {
	t.Parallel()
	t.Run("emits the trailing partial", func(t *testing.T) {
		t.Parallel()
		sp := splitter{}
		var got []string
		emit := func(line []byte) error { got = append(got, string(line)); return nil }
		if err := sp.push([]byte("a\ntrailing"), emit); err != nil {
			t.Fatal(err)
		}
		if err := sp.flush(emit); err != nil {
			t.Fatal(err)
		}
		if want := []string{"a", "trailing"}; !equalStrings(got, want) {
			t.Fatalf("lines = %q, want %q", got, want)
		}
		if sp.pending() != 0 {
			t.Fatalf("pending = %d, want 0", sp.pending())
		}
	})
	t.Run("does not resurrect a discarded over-long tail", func(t *testing.T) {
		t.Parallel()
		sp := splitter{max: 2}
		var got []string
		emit := func(line []byte) error { got = append(got, string(line)); return nil }
		if err := sp.push([]byte("abcdef"), emit); err != nil {
			t.Fatal(err)
		}
		if err := sp.flush(emit); err != nil {
			t.Fatal(err)
		}
		if want := []string{"ab"}; !equalStrings(got, want) {
			t.Fatalf("lines = %q, want %q", got, want)
		}
	})
}

func TestSplitterPropagatesEmitError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("cancelled")
	sp := splitter{}
	n := 0
	emit := func([]byte) error {
		n++
		return sentinel
	}
	if err := sp.push([]byte("a\nb\nc\n"), emit); !errors.Is(err, sentinel) {
		t.Fatalf("push = %v, want %v", err, sentinel)
	}
	if n != 1 {
		t.Fatalf("emit called %d times, want 1 (push must stop at the first error)", n)
	}
}

// splitAll runs data through a splitter in chunks of size n (plus a final
// flush) and returns the lines it emitted.
func splitAll(data []byte, n int) []string {
	sp := splitter{max: maxLineBytes}
	var got []string
	emit := func(line []byte) error {
		got = append(got, string(line))
		return nil
	}
	for len(data) > 0 {
		c := min(n, len(data))
		_ = sp.push(data[:c], emit) // emit never fails here
		data = data[c:]
	}
	_ = sp.flush(emit)
	return got
}

// wantLines is the reference implementation: split on newlines, drop the empty
// remainder after a trailing newline, trim CR. It is what bytes.Split would
// give a caller who had the whole stream in memory at once, which is exactly
// the property the splitter exists to preserve for a caller who does not.
func wantLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	parts := bytes.Split(data, []byte("\n"))
	if len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, string(trimCR(p)))
	}
	return out
}

// Chunk boundaries are an accident of the network and the filesystem, so the
// splitter's output must not depend on them at all.
func TestSplitterIsIndependentOfChunkBoundaries(t *testing.T) {
	t.Parallel()
	inputs := []string{
		"",
		"\n",
		"a\nb\nc\n",
		"a\nb\nc",
		"no newline at all",
		"\n\n\n",
		"crlf\r\nand\r\nmore\r\n",
		"trailing\rcr\n",
		"Failed password for root from 10.0.0.1 port 22\nAccepted publickey for alice\n",
		"\x00binary\xff\ndata\n",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			data := []byte(in)
			want := wantLines(data)
			for n := 1; n <= len(data)+1; n++ {
				if got := splitAll(data, n); !equalStrings(got, want) {
					t.Fatalf("chunk size %d: lines = %q, want %q", n, got, want)
				}
			}
		})
	}
}

// FuzzSplitterPush asserts the same property on arbitrary input: reassembling
// a byte stream cut at an arbitrary point must equal splitting it whole.
func FuzzSplitterPush(f *testing.F) {
	f.Add([]byte("a\nb\n"), uint8(1))
	f.Add([]byte("partial"), uint8(3))
	f.Add([]byte("\r\n\r\n"), uint8(2))
	f.Add([]byte("one\ntwo\nthree"), uint8(7))
	f.Fuzz(func(t *testing.T, data []byte, chunk uint8) {
		got := splitAll(data, int(chunk)+1)
		if want := wantLines(data); !equalStrings(got, want) {
			t.Fatalf("chunk size %d: lines = %q, want %q", int(chunk)+1, got, want)
		}
	})
}

// takeTruncated is how a source moves the count into its own stats, so it has
// to report each truncation exactly once.
func TestSplitterTakeTruncated(t *testing.T) {
	t.Parallel()
	sp := splitter{max: 2}
	emit := func([]byte) error { return nil }

	if n := sp.takeTruncated(); n != 0 {
		t.Errorf("fresh splitter reported %d truncations, want 0", n)
	}
	if err := sp.push([]byte("aaaa\nbbbb\n"), emit); err != nil {
		t.Fatal(err)
	}
	if n := sp.takeTruncated(); n != 2 {
		t.Errorf("takeTruncated = %d, want 2", n)
	}
	if n := sp.takeTruncated(); n != 0 {
		t.Errorf("second takeTruncated = %d, want 0 (a delta, not a total)", n)
	}
	if err := sp.push([]byte("cccc\n"), emit); err != nil {
		t.Fatal(err)
	}
	if n := sp.takeTruncated(); n != 1 {
		t.Errorf("takeTruncated after one more = %d, want 1", n)
	}
	// reset clears buffered bytes, not statistics.
	sp.reset()
	if sp.truncated != 3 {
		t.Errorf("total truncated = %d, want 3 preserved across reset", sp.truncated)
	}
}

func TestSplitterReset(t *testing.T) {
	t.Parallel()
	sp := splitter{max: 4}
	emit := func([]byte) error { return nil }
	if err := sp.push([]byte("partial"), emit); err != nil { // enters discard mode
		t.Fatal(err)
	}
	sp.reset()
	var got []string
	if err := sp.push([]byte("clean\n"), func(l []byte) error {
		got = append(got, string(l))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"clea"}; !equalStrings(got, want) {
		t.Fatalf("lines = %q, want %q (reset must clear discard state)", got, want)
	}
}

// The arena is the mechanism behind the package's promise that Event.Raw is
// safe to retain: no byte it hands out may ever be rewritten, and a consumer's
// append must not reach into the next line.
func TestArenaHandsOutStableSlices(t *testing.T) {
	t.Parallel()
	var a arena
	var got [][]byte
	want := make([]string, 0, 5000)
	for i := range 5000 {
		s := strings.Repeat(string(rune('a'+i%26)), 1+i%200)
		got = append(got, a.copy([]byte(s)))
		want = append(want, s)
	}
	for i, b := range got {
		if string(b) != want[i] {
			t.Fatalf("slice %d = %q, want %q", i, b, want[i])
		}
		if len(b) != cap(b) {
			t.Fatalf("slice %d has spare capacity %d; append would clobber the next line", i, cap(b)-len(b))
		}
	}
	// An append by a consumer must not corrupt a neighbour.
	first := append(got[0], 'X') //nolint:gocritic // deliberately exercising append
	_ = first
	for i, b := range got {
		if string(b) != want[i] {
			t.Fatalf("after consumer append, slice %d = %q, want %q", i, b, want[i])
		}
	}
}

func TestArenaOversizedAllocation(t *testing.T) {
	t.Parallel()
	var a arena
	big := bytes.Repeat([]byte("z"), arenaBlock*2)
	got := a.copy(big)
	if !bytes.Equal(got, big) {
		t.Fatal("oversized copy corrupted")
	}
	small := a.copy([]byte("after"))
	if string(small) != "after" {
		t.Fatalf("copy after oversized = %q", small)
	}
}
