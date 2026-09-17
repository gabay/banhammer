package source

import "bytes"

// stripSyslog removes a syslog framing prefix, returning just the message.
//
// Two shapes are recognised:
//
//	RFC3164: <34>Oct 11 22:14:15 mymachine su[123]: message
//	RFC5424: <34>1 2003-10-11T22:14:15.003Z host su - ID47 [sd] message
//
// Anything that does not parse is returned unchanged rather than dropped: a
// sender we do not understand must still be matchable. A valid <PRI> is always
// removed though, even when the rest of the header is unrecognised, because it
// is unambiguous and would otherwise leak into every pattern.
func stripSyslog(line []byte) []byte {
	rest := line
	if len(rest) > 0 && rest[0] == '<' {
		i := bytes.IndexByte(rest, '>')
		// PRI is at most 3 digits ("<191>").
		if i < 2 || i > 4 || !allDigits(rest[1:i]) {
			return line
		}
		rest = rest[i+1:]
	}
	if msg, ok := strip5424(rest); ok {
		return msg
	}
	if msg, ok := strip3164(rest); ok {
		return msg
	}
	return rest
}

// strip5424 handles "1 TIMESTAMP HOST APP PROCID MSGID SD [MSG]".
func strip5424(b []byte) ([]byte, bool) {
	ver, rest, ok := cutField(b)
	// The version is a single non-zero digit in practice; anything else is
	// not RFC5424.
	if !ok || len(ver) != 1 || ver[0] < '1' || ver[0] > '9' {
		return nil, false
	}
	// TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
	for range 5 {
		if _, rest, ok = cutField(rest); !ok {
			return nil, false
		}
	}
	// STRUCTURED-DATA: either "-" or one or more [id key="value"] elements.
	switch {
	case len(rest) == 0:
		return nil, false
	case rest[0] == '-':
		rest = rest[1:]
	case rest[0] == '[':
		end, ok := endOfStructuredData(rest)
		if !ok {
			return nil, false
		}
		rest = rest[end:]
	default:
		return nil, false
	}
	if len(rest) == 0 {
		return nil, true // header-only message
	}
	if rest[0] != ' ' {
		return nil, false
	}
	return trimBOM(rest[1:]), true
}

// endOfStructuredData returns the index just past the final ] of a run of
// structured-data elements, honouring the \] escape.
func endOfStructuredData(b []byte) (int, bool) {
	i := 0
	for i < len(b) && b[i] == '[' {
		i++
		closed := false
		for i < len(b) {
			switch b[i] {
			case '\\':
				i += 2 // skip the escaped byte, whatever it is
				continue
			case ']':
				i++
				closed = true
			default:
				i++
				continue
			}
			break
		}
		if !closed {
			return 0, false
		}
	}
	if i == 0 {
		return 0, false
	}
	return i, true
}

// strip3164 handles "TIMESTAMP HOST TAG[pid]: MSG", accepting both the classic
// "Oct 11 22:14:15" stamp and the ISO-8601 stamp many senders emit instead.
func strip3164(b []byte) ([]byte, bool) {
	rest, ok := cutTimestamp3164(b)
	if !ok {
		return nil, false
	}
	// HOSTNAME
	if _, rest, ok = cutField(rest); !ok {
		return nil, false
	}
	// TAG, optionally "name[pid]", terminated by ':'. Senders that omit the
	// tag entirely are tolerated: the message simply starts here.
	if tag, after, ok := cutField(rest); ok && isTag(tag) {
		rest = after
	}
	return rest, true
}

func cutTimestamp3164(b []byte) ([]byte, bool) {
	// "Mmm dd hh:mm:ss" — the day may be space-padded, giving a double space.
	if len(b) >= 15 && isAlpha(b[0]) && isAlpha(b[1]) && isAlpha(b[2]) && b[3] == ' ' {
		rest := b[4:]
		for len(rest) > 0 && rest[0] == ' ' {
			rest = rest[1:]
		}
		day, rest, ok := cutField(rest)
		if !ok || len(day) < 1 || len(day) > 2 || !allDigits(day) {
			return nil, false
		}
		clock, rest, ok := cutField(rest)
		if !ok || !isClock(clock) {
			return nil, false
		}
		return rest, true
	}
	// Many senders emit an ISO-8601/RFC3339 stamp in an otherwise 3164-shaped
	// line. The test here is deliberately loose: one space-delimited field, at
	// least 10 bytes, starting "YYYY-". It does not look for the 'T', the
	// clock or the zone, because senders vary ("2006-01-02T15:04:05Z",
	// "2006-01-02 15:04:05" — where the time is a *separate* field — and
	// fractional or offset suffixes), and because being wrong here is cheap:
	// the caller falls back to returning the line unchanged, so a header we
	// misjudge is still matchable, just with its timestamp attached.
	stamp, rest, ok := cutField(b)
	if !ok || len(stamp) < 10 || !allDigits(stamp[0:4]) || stamp[4] != '-' {
		return nil, false
	}
	return rest, true
}

// isTag reports whether f looks like an RFC3164 TAG: a short token ending in
// ':' that is not obviously the start of the message.
func isTag(f []byte) bool {
	if len(f) < 2 || len(f) > 64 || f[len(f)-1] != ':' {
		return false
	}
	return !bytes.ContainsAny(f[:len(f)-1], " :")
}

// cutField splits off the next space-delimited field.
func cutField(b []byte) (field, rest []byte, ok bool) {
	i := bytes.IndexByte(b, ' ')
	if i < 0 {
		return nil, nil, false
	}
	return b[:i], b[i+1:], i > 0
}

func isClock(b []byte) bool {
	if len(b) != 8 || b[2] != ':' || b[5] != ':' {
		return false
	}
	return allDigits(b[0:2]) && allDigits(b[3:5]) && allDigits(b[6:8])
}

func allDigits(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// trimBOM drops the UTF-8 BOM RFC5424 allows in front of the message.
func trimBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
}
