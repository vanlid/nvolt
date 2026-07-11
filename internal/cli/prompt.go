package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// maxSelectAttempts bounds how many bad inputs selectOption tolerates before
// giving up, so a wizard driven by a non-interactive/garbage reader (or a
// confused user) fails instead of looping forever.
const maxSelectAttempts = 3

// selectOption prints title followed by a 1-based numbered list of options to
// w, then prompts on w and reads a line from r until the user picks a valid
// option. It returns the 0-based index of the chosen option. Taking w/r
// (rather than os.Stdout/os.Stdin directly) makes it unit-testable with a
// bytes.Buffer/strings.Reader; selectOptionStdio below wires it to the real
// terminal.
func selectOption(w io.Writer, r io.Reader, title string, options []string) (int, error) {
	if len(options) == 0 {
		return 0, fmt.Errorf("selectOption: no options to choose from")
	}

	fmt.Fprintln(w, title)
	for i, opt := range options {
		fmt.Fprintf(w, "  [%d] %s\n", i+1, opt)
	}

	scanner := bufio.NewScanner(r)
	for attempt := 0; attempt < maxSelectAttempts; attempt++ {
		fmt.Fprint(w, "Enter a number: ")
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return 0, fmt.Errorf("selectOption: reading input: %w", err)
			}
			return 0, fmt.Errorf("selectOption: no input provided")
		}
		line := strings.TrimSpace(scanner.Text())
		n, err := strconv.Atoi(line)
		if err != nil || n < 1 || n > len(options) {
			fmt.Fprintf(w, "invalid selection %q; enter a number between 1 and %d\n", line, len(options))
			continue
		}
		return n - 1, nil
	}
	return 0, fmt.Errorf("selectOption: too many invalid selections")
}

// selectOptionStdio is selectOption wired to the real terminal (os.Stdout/
// os.Stdin). Callers driving the interactive pkcs11 wizard use this; tests
// exercise selectOption directly with injected reader/writer.
func selectOptionStdio(title string, options []string) (int, error) {
	return selectOption(os.Stdout, os.Stdin, title, options)
}
