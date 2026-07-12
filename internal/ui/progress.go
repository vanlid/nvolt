package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// ProgressBar represents a simple progress indicator
type ProgressBar struct {
	total     int
	current   int
	width     int
	label     string
	startTime time.Time
	output    io.Writer
	enabled   bool
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int, label string) *ProgressBar {
	return &ProgressBar{
		total:     total,
		current:   0,
		width:     40,
		label:     label,
		startTime: time.Now(),
		output:    os.Stdout,
		enabled:   true,
	}
}

// SetEnabled enables or disables the progress bar
func (p *ProgressBar) SetEnabled(enabled bool) {
	p.enabled = enabled
}

// Increment increments the progress by 1
func (p *ProgressBar) Increment() {
	p.Add(1)
}

// Add increments the progress by n
func (p *ProgressBar) Add(n int) {
	p.current += n
	if p.current > p.total {
		p.current = p.total
	}
	p.render()
}

// Finish completes the progress bar
func (p *ProgressBar) Finish() {
	p.current = p.total
	p.render()
	fmt.Fprintln(p.output)
}

// render draws the progress bar
func (p *ProgressBar) render() {
	if !p.enabled || p.total == 0 {
		return
	}

	percent := float64(p.current) / float64(p.total)
	filled := int(percent * float64(p.width))

	bar := strings.Repeat("█", filled) + strings.Repeat("░", p.width-filled)

	elapsed := time.Since(p.startTime)
	eta := time.Duration(0)
	if p.current > 0 {
		eta = time.Duration(float64(elapsed) * (float64(p.total-p.current) / float64(p.current)))
	}

	// Clear line and print progress
	fmt.Fprintf(p.output, "\r%s [%s] %d/%d (%.0f%%) ETA: %s",
		p.label,
		bar,
		p.current,
		p.total,
		percent*100,
		eta.Round(time.Second))
}

// Spinner represents a simple spinner for operations without known duration
type Spinner struct {
	label   string
	chars   []rune
	index   int
	output  io.Writer
	enabled bool
	done    chan bool
}

// NewSpinner creates a new spinner
func NewSpinner(label string) *Spinner {
	return &Spinner{
		label:   label,
		chars:   []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'},
		index:   0,
		output:  os.Stdout,
		enabled: true,
		done:    make(chan bool),
	}
}

// SetEnabled enables or disables the spinner
func (s *Spinner) SetEnabled(enabled bool) {
	s.enabled = enabled
}

// Start starts the spinner animation
func (s *Spinner) Start() {
	if !s.enabled {
		fmt.Fprintln(s.output, s.label)
		return
	}

	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.render()
				s.index = (s.index + 1) % len(s.chars)
			case <-s.done:
				return
			}
		}
	}()
}

// Stop stops the spinner
func (s *Spinner) Stop() {
	if s.enabled {
		s.done <- true
		fmt.Fprintf(s.output, "\r%s\n", strings.Repeat(" ", len(s.label)+5))
	}
}

// Success stops the spinner and shows success
func (s *Spinner) Success(message string) {
	s.Stop()
	Success("%s", message)
}

// render draws the current spinner frame
func (s *Spinner) render() {
	fmt.Fprintf(s.output, "\r%c %s", s.chars[s.index], s.label)
}
