package main

import "testing"

// TestRun_ActionValidation covers the action-count checks that used to call os.Exit directly.
func TestRun_ActionValidation(t *testing.T) {
	if err := run(nil); err == nil {
		t.Errorf("expected error with no action")
	}
	if err := run([]string{"-c", "-p"}); err == nil {
		t.Errorf("expected error with two actions")
	}
	if err := run([]string{"-h"}); err != nil {
		t.Errorf("-h should succeed, got %v", err)
	}
}
