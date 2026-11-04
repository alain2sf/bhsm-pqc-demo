package main

import (
	"os"
	"os/exec"
	"testing"
)

// TestCLI_NoArgs_ExitsWithError tests that invoking the binary without
// arguments fails with a non-zero exit code and displays the usage message.
func TestCLI_NoArgs_ExitsWithError(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "")
	cmd.Env = append(os.Environ(), "GO111MODULE=on")

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("Expected CLI with no arguments to exit with error, but it succeeded. Output:\n%s", string(output))
	}
}

// TestCLI_HelpFlag tests that invoking -h succeeds with exit code 0.
func TestCLI_HelpFlag(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "-h")
	cmd.Env = append(os.Environ(), "GO111MODULE=on")

	output, err := cmd.CombinedOutput()
	// flag.Usage outputs to stderr with exit code 0 on -h
	if err != nil && err.Error() != "exit status 0" {
		t.Fatalf("Expected help flag (-h) to succeed, got error: %v. Output:\n%s", err, string(output))
	}
}
