package source

import "bytes"

// splitter reassembles newline-delimited lines from arbitrary byte chunks.
//
// It exists instead of bufio.Scanner because a tailer must never emit an
// unterminated line: a writer that flushes half a line must block us until the
// rest arrives, whereas Scanner happily yields the trailing fragment at EOF —
// and a tailer hits EOF constantly. A splitter is owned by exactly one
// goroutine.
type splitter struct {
	max       int    // longest line emitted; 0 means maxLineBytes
	carry     []byte // bytes of an incomplete line seen so far
	discard   bool   // swallowing the tail of an over-long line
	truncated uint64 // over-long lines emitted truncated, since creation
	reported  uint64 // value of truncated at the last takeTruncated
}

func (s *splitter) limit() int {
	if s.max > 0 {
		return s.max
	}
	return maxLineBytes
}

// push feeds a chunk through the splitter, calling emit once per complete
// line (without the newline, and with a trailing CR removed). It stops and
// returns the first error emit reports; state is then undefined, which is fine
// because the only error is context cancellation.
func (s *splitter) push(chunk []byte, emit func([]byte) error) error {
	max := s.limit()
	for len(chunk) > 0 {
		if s.discard {
			i := bytes.IndexByte(chunk, '\n')
			if i < 0 {
				return nil
			}
			chunk, s.discard = chunk[i+1:], false
			continue
		}
		i := bytes.IndexByte(chunk, '\n')
		if i < 0 {
			// Incomplete line: hold it until the newline arrives.
			s.carry = append(s.carry, chunk...)
			// Strictly greater, exactly as on the newline path below: a
			// line of exactly max bytes is *not* over-long, and treating it
			// as such here would also swallow its newline as the start of
			// the discarded tail, corrupting the following line.
			if len(s.carry) > max {
				// Over-long and still no newline. Emit the head so
				// a match cannot be hidden behind padding, then
				// swallow the rest of the line.
				s.truncated++
				line := s.carry[:max]
				s.discard = true
				err := emit(trimCR(line))
				s.carry = s.carry[:0]
				return err
			}
			return nil
		}
		line := chunk[:i]
		chunk = chunk[i+1:]
		if len(s.carry) > 0 {
			s.carry = append(s.carry, line...)
			line = s.carry
		}
		if len(line) > max {
			s.truncated++
			line = line[:max]
		}
		err := emit(trimCR(line))
		s.carry = s.carry[:0]
		if err != nil {
			return err
		}
	}
	return nil
}

// flush emits a trailing unterminated line. Only stream sources whose end is
// authoritative (a closed TCP connection, stdin EOF) may call it; a file
// tailer must not, because "end of file" there just means "the writer has not
// finished the line yet".
func (s *splitter) flush(emit func([]byte) error) error {
	if s.discard {
		s.discard = false
		s.carry = s.carry[:0]
		return nil
	}
	if len(s.carry) == 0 {
		return nil
	}
	line := s.carry
	s.carry = s.carry[:0]
	return emit(trimCR(line))
}

// pending reports how many buffered bytes belong to an incomplete line. The
// tailer subtracts it from the file offset so a checkpoint always lands on a
// line boundary and a restart re-reads the partial line rather than losing it.
func (s *splitter) pending() int { return len(s.carry) }

// takeTruncated returns how many lines have been truncated since the previous
// call. It is a delta rather than a total because the caller aggregates across
// splitters (one per connection, one per tailed file) into a single counter,
// and because reading it must be cheap enough to do after every pump.
func (s *splitter) takeTruncated() uint64 {
	n := s.truncated - s.reported
	s.reported = s.truncated
	return n
}

// reset drops buffered state, used when the underlying file is replaced or
// truncated and the partial line can never be completed.
func (s *splitter) reset() {
	s.carry = s.carry[:0]
	s.discard = false
}

func trimCR(line []byte) []byte {
	if n := len(line); n > 0 && line[n-1] == '\r' {
		return line[:n-1]
	}
	return line
}
