//go:build race

package decode

// raceEnabled lets the allocation tests skip themselves: the race detector's
// instrumentation defeats the compiler optimizations (notably the alloc-free
// string(b) comparison) that those tests exist to verify.
const raceEnabled = true
