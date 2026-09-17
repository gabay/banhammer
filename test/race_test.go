//go:build race

package test

// raceEnabled lets the allocation tests skip themselves: the race detector's
// instrumentation adds bookkeeping allocations the tested code does not make,
// so a zero-allocation assertion can never hold under -race.
const raceEnabled = true
