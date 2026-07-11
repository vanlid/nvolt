package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestSelectOptionValidPick proves a valid 1-based number picks the right
// 0-based index and echoes the title/options to w.
func TestSelectOptionValidPick(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader("2\n")

	got, err := selectOption(&out, in, "Pick one:", []string{"alpha", "beta", "gamma"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1 {
		t.Fatalf("expected index 1, got %d", got)
	}
	if !strings.Contains(out.String(), "[2] beta") {
		t.Fatalf("expected option listing in output:\n%s", out.String())
	}
}

// TestSelectOptionOutOfRangeThenSuccess proves an out-of-range pick is
// rejected and a subsequent valid pick on retry succeeds.
func TestSelectOptionOutOfRangeThenSuccess(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader("5\n1\n")

	got, err := selectOption(&out, in, "Pick one:", []string{"alpha", "beta"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0 {
		t.Fatalf("expected index 0, got %d", got)
	}
	if !strings.Contains(out.String(), "invalid selection") {
		t.Fatalf("expected an invalid-selection notice in output:\n%s", out.String())
	}
}

// TestSelectOptionNonNumericFails proves non-numeric input, repeated past the
// retry budget, returns an error instead of looping forever.
func TestSelectOptionNonNumericFails(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader("foo\nbar\nbaz\nqux\n")

	if _, err := selectOption(&out, in, "Pick one:", []string{"alpha", "beta"}); err == nil {
		t.Fatal("expected error for repeated non-numeric input, got nil")
	}
}

// TestSelectOptionEmptyInputFails proves EOF with no input at all is an
// error, not a hang or a silently-wrong default index.
func TestSelectOptionEmptyInputFails(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader("")

	if _, err := selectOption(&out, in, "Pick one:", []string{"alpha", "beta"}); err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
}

// TestSelectOptionNoOptionsFails proves an empty options slice is rejected
// up front rather than producing a confusing prompt.
func TestSelectOptionNoOptionsFails(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader("1\n")

	if _, err := selectOption(&out, in, "Pick one:", nil); err == nil {
		t.Fatal("expected error for no options, got nil")
	}
}
