//go:build unix

package store

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"testing"
	"time"
)

// lockHelperEnv makes the test binary re-exec itself as a "second daemon"
// that holds the state directory lock until it is killed. flock ownership
// dies with the process, which is exactly the property under test and cannot
// be observed from within a single process.
const lockHelperEnv = "BANHAMMER_STORE_LOCK_HELPER_DIR"

func TestMain(m *testing.M) {
	if dir := os.Getenv(lockHelperEnv); dir != "" {
		os.Exit(runLockHelper(dir))
	}
	os.Exit(m.Run())
}

func runLockHelper(dir string) int {
	s, err := Open(dir)
	if err != nil {
		fmt.Printf("ERR %v\n", err)
		return 1
	}
	defer s.Close() //nolint:errcheck // the parent kills this process
	fmt.Println("LOCKED")
	// Block without sleeping: the parent kills us, or closes our stdin.
	_, _ = io.Copy(io.Discard, os.Stdin) // errors here are irrelevant; we are exiting
	return 0
}

func TestLockIsHeldAcrossProcessesAndReleasedOnDeath(t *testing.T) {
	// Not parallel: it forks a copy of the test binary.
	dir := t.TempDir()

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), lockHelperEnv+"="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if _, err := cmd.StdinPipe(); err != nil { // keeps the child blocked on stdin
		t.Fatalf("stdin pipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	killed := false
	defer func() {
		if !killed {
			_ = cmd.Process.Kill() // best effort cleanup on a failed test
			_ = cmd.Wait()
		}
	}()

	line := make(chan string, 1)
	go func() {
		s, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil {
			line <- "EOF " + err.Error()
			return
		}
		line <- strings.TrimSpace(s)
	}()
	var got string
	select {
	case got = <-line:
	case <-time.After(30 * time.Second): // failure guard only, not logic under test
		t.Fatal("timed out waiting for the helper to take the lock")
	}
	if got != "LOCKED" {
		t.Fatalf("helper did not take the lock: %q", got)
	}

	if _, err := Open(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("Open while another process holds the lock = %v, want ErrLocked", err)
	}

	// SIGKILL: no chance to clean up, so only the kernel can release the lock.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	_, _ = cmd.Process.Wait() // the exit status of a killed process is uninteresting
	killed = true

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open after the lock holder died: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestLockFileSymlinkIsRefused(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	elsewhere := filepath.Join(t.TempDir(), "someone-elses-file")
	if err := os.WriteFile(elsewhere, nil, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(dir, lockFileName)); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// Following the link would take the flock on an unrelated file, so two
	// daemons could both believe they own this directory.
	_, err := Open(dir)
	if err == nil {
		t.Fatal("Open followed a symlinked lock file")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error = %v, want it to name the symlink problem", err)
	}
}
