//go:build race

package rule

// raceEnabled lets the allocation tests skip themselves: the race detector's
// instrumentation defeats the compiler optimizations those tests verify.
const raceEnabled = true
