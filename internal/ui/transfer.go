package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mfkrypt/smblens/internal/smbclient"
	"github.com/mfkrypt/smblens/internal/termtext"
)

// transferDirection identifies an upload, a file download, or a recursive
// folder download.
type transferDirection int

const (
	transferUpload transferDirection = iota
	transferDownload
	transferDownloadTree
)

// transferEvent is streamed from the transfer goroutine.
type transferEvent struct {
	done     int64
	total    int64
	finished bool
	err      error

	// Recursive folder download fields.
	phase      string
	filesDone  int
	filesTotal int
	current    string
	failed     int
	skipped    int
	failures   []string
}

type transferEventMsg struct {
	event transferEvent
}

type transferChannelClosedMsg struct{}

// transferState drives the transfer dialog and its progress display.
type transferState struct {
	direction transferDirection
	host      string
	shareName string
	remote    string
	local     string

	done     int64
	total    int64
	started  time.Time
	lastTime time.Time
	lastDone int64
	rate     float64

	finished  bool
	cancelled bool
	err       error

	// Recursive folder download state.
	phase      string
	filesDone  int
	filesTotal int
	current    string
	failed     int
	skipped    int
	failures   []string

	cancel context.CancelFunc
	ch     <-chan transferEvent
	theme  *theme
}

// newTransferState builds the dialog state for an upload, file download or recursive folder download.
func newTransferState(direction transferDirection, host, shareName, remote, local string, cancel context.CancelFunc, ch <-chan transferEvent, t *theme) *transferState {
	now := time.Now()
	state := &transferState{
		direction: direction,
		host:      host,
		shareName: shareName,
		remote:    remote,
		local:     local,
		started:   now,
		lastTime:  now,
		cancel:    cancel,
		ch:        ch,
		theme:     t,
	}
	if direction == transferDownloadTree {
		state.phase = smbclient.TreePhaseScanning
	}
	return state
}

// runTransfer starts the copy and streams progress on a channel.
func runTransfer(ctx context.Context, cancel context.CancelFunc, direction transferDirection, share *smbclient.Share, local, remote string, overwrite bool) <-chan transferEvent {
	ch := make(chan transferEvent, 32)

	go func() {
		defer close(ch)

		var final transferEvent
		switch direction {
		case transferDownloadTree:
			var (
				lastPhase string
				lastSent  time.Time
			)
			progress := func(p smbclient.TreeDownloadProgress) {
				if p.Phase == lastPhase && time.Since(lastSent) < 120*time.Millisecond {
					return
				}
				lastPhase = p.Phase
				lastSent = time.Now()
				select {
				case ch <- transferEvent{
					phase:      p.Phase,
					done:       p.BytesDone,
					total:      p.BytesTotal,
					filesDone:  p.FilesDone,
					filesTotal: p.FilesTotal,
					current:    p.Current,
				}:
				default:
				}
			}

			result, err := share.DownloadTree(ctx, remote, local, progress)
			final = transferEvent{
				finished:   true,
				err:        err,
				done:       result.Bytes,
				total:      result.BytesTotal,
				filesDone:  result.Files,
				filesTotal: result.FilesTotal,
				failed:     result.Failed,
				skipped:    result.Skipped,
				failures:   result.Errors,
				phase:      "done",
			}

		default:
			var (
				lastDone int64
				lastSent time.Time
			)
			progress := func(done, total int64) {
				lastDone = done
				if time.Since(lastSent) < 100*time.Millisecond && done < total {
					return
				}
				lastSent = time.Now()
				select {
				case ch <- transferEvent{done: done, total: total}:
				default:
				}
			}

			var err error
			if direction == transferUpload {
				err = share.Upload(ctx, local, remote, overwrite, progress)
			} else {
				err = share.Download(ctx, remote, local, progress)
			}

			final = transferEvent{finished: true, err: err}
			if err == nil {
				final.done, final.total = lastDone, lastDone
			}
		}

		select {
		case ch <- final:
		case <-time.After(2 * time.Second):
		}
	}()

	return ch
}

// waitForTransferEvent waits for the next progress event or reports that the channel closed.
func waitForTransferEvent(ch <-chan transferEvent) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-ch
		if !ok {
			return transferChannelClosedMsg{}
		}
		return transferEventMsg{event: event}
	}
}

// update merges one progress event into the transfer state and smooths the transfer rate.
func (t *transferState) update(event transferEvent) {
	if event.phase != "" {
		t.phase = event.phase
	}
	if t.direction == transferDownloadTree {
		if event.filesTotal > 0 {
			t.filesTotal = event.filesTotal
		}
		if event.filesDone > 0 || t.phase == smbclient.TreePhaseDownloading {
			t.filesDone = event.filesDone
		}
		if event.current != "" {
			t.current = event.current
		}
		if event.failed > 0 {
			t.failed = event.failed
		}
		if event.skipped > 0 {
			t.skipped = event.skipped
		}
		if event.failures != nil {
			t.failures = event.failures
		}
	}

	now := time.Now()
	if event.done != t.done {
		delta := event.done - t.lastDone
		elapsed := now.Sub(t.lastTime).Seconds()
		if elapsed > 0.3 && delta > 0 {
			instant := float64(delta) / elapsed
			if t.rate == 0 {
				t.rate = instant
			} else {
				t.rate = 0.7*t.rate + 0.3*instant
			}
			t.lastTime = now
			t.lastDone = event.done
		}
		t.done = event.done
	}
	if event.total > 0 {
		t.total = event.total
	}
	if event.finished {
		t.finished = true
		t.err = event.err
		if t.direction == transferDownloadTree {
			t.filesDone = event.filesDone
			t.filesTotal = event.filesTotal
			t.failed = event.failed
			t.skipped = event.skipped
			if event.failures != nil {
				t.failures = event.failures
			}
			t.done = event.done
			t.total = event.total
			t.phase = "done"
		}
		if event.err != nil && (t.cancelled || event.err == context.Canceled || strings.Contains(event.err.Error(), context.Canceled.Error())) {
			t.cancelled = true
			t.err = nil
		}
	}
}

// cancelTransfer requests cancellation of an unfinished transfer.
func (t *transferState) cancelTransfer() {
	if t.finished || t.cancel == nil {
		return
	}
	t.cancelled = true
	t.cancel()
}

// title returns the dialog title appropriate to the transfer direction.
func (t *transferState) title() string {
	switch t.direction {
	case transferUpload:
		return "Upload"
	case transferDownloadTree:
		return "Download folder"
	default:
		return "Download"
	}
}

// failureError describes a partially successful folder download.
func (t *transferState) failureError() error {
	if t.failed == 0 && t.skipped == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Downloaded %d of %d files (%s).\n", t.filesDone, t.filesTotal, formatSize(t.done))
	if t.failed > 0 {
		fmt.Fprintf(&b, "%d problem%s.\n", t.failed, plural(t.failed, "", "s"))
	}
	if t.skipped > 0 {
		fmt.Fprintf(&b, "%d special entr%s skipped.\n", t.skipped, plural(t.skipped, "y", "ies"))
	}
	for _, failure := range t.failures {
		b.WriteString(failure + "\n")
	}
	return errors.New(strings.TrimRight(b.String(), "\n"))
}

// View renders the transfer dialog body.
func (t *transferState) View(width int) string {
	if t.direction == transferDownloadTree {
		return t.treeView(width)
	}
	return t.fileView(width)
}

// fileView renders a single-file upload or download, including progress, rate and errors.
func (t *transferState) fileView(width int) string {
	p := t.theme
	verb := "Downloading"
	if t.direction == transferUpload {
		verb = "Uploading"
	}

	remote := `\\` + t.host + `\` + t.shareName + `\` + strings.ReplaceAll(t.remote, "/", `\`)
	var b strings.Builder
	if t.finished {
		switch {
		case t.cancelled:
			fmt.Fprintf(&b, "%s cancelled.\n", verb)
		case t.err != nil:
			fmt.Fprintf(&b, "%s failed.\n", verb)
		default:
			fmt.Fprintf(&b, "%s complete.\n", verb)
		}
	} else {
		fmt.Fprintf(&b, "%s…\n", verb)
	}
	fmt.Fprintf(&b, "%s\n", termtext.Clean(remote))
	if t.direction == transferUpload {
		fmt.Fprintf(&b, "from %s\n", termtext.Clean(t.local))
	} else {
		fmt.Fprintf(&b, "to %s\n", termtext.Clean(t.local))
	}

	ratio := percent(t.done, t.total)
	line := fmt.Sprintf("[%s] %3.0f%%  %s", t.bar(width, ratio), ratio*100, t.sizeLine())
	if !t.finished {
		line += t.rateSuffix()
	}
	b.WriteString("\n" + line + "\n")

	if t.finished {
		if t.err != nil {
			b.WriteString("\n" + p.danger.Render(smbclient.Describe(t.err)) + "\n")
			b.WriteString(p.muted.Render("Press i for details, esc to close."))
		} else if t.cancelled {
			b.WriteString("\n" + p.muted.Render("esc to close"))
		} else {
			b.WriteString("\n" + p.muted.Render("esc or enter to close"))
		}
	} else {
		b.WriteString("\n" + p.muted.Render("esc cancels the transfer"))
	}

	return b.String()
}

// treeView renders a recursive folder download through its scanning, downloading and summary phases.
func (t *transferState) treeView(width int) string {
	p := t.theme
	remote := `\\` + t.host + `\` + t.shareName + `\` + strings.ReplaceAll(t.remote, "/", `\`)

	status := "Downloading…"
	switch {
	case t.finished:
		switch {
		case t.cancelled:
			status = "Download cancelled."
		case t.err != nil:
			status = "Download failed."
		case t.failed > 0 || t.skipped > 0:
			status = "Download finished with problems."
		default:
			status = "Download complete."
		}
	case t.phase == smbclient.TreePhaseScanning:
		status = "Scanning the remote folder…"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", p.accent.Render(status))
	fmt.Fprintf(&b, "%s\n", termtext.Clean(remote))
	fmt.Fprintf(&b, "to %s\n", termtext.Clean(t.local))

	if !t.finished && t.phase == smbclient.TreePhaseScanning {
		fmt.Fprintf(&b, "\n%d file%s found · %s so far\n",
			t.filesDone, plural(t.filesDone, "", "s"), formatSize(t.done))
		b.WriteString("\n" + p.muted.Render("esc cancels the download"))
		return b.String()
	}

	ratio := percent(t.done, t.total)
	if t.total == 0 && t.filesTotal > 0 {
		ratio = percent(int64(t.filesDone), int64(t.filesTotal))
	}
	line := fmt.Sprintf("[%s] %3.0f%%  %s", t.bar(width, ratio), ratio*100, t.sizeLine())
	if !t.finished {
		line += t.rateSuffix()
	}
	b.WriteString("\n" + line + "\n")

	if !t.finished {
		current := termtext.Clean(t.current)
		if t.filesTotal > 0 {
			n := t.filesDone + 1
			if n > t.filesTotal {
				n = t.filesTotal
			}
			fmt.Fprintf(&b, "file %d of %d · %s\n", n, t.filesTotal, current)
		} else if current != "" {
			fmt.Fprintf(&b, "%s\n", current)
		}
		b.WriteString("\n" + p.muted.Render("esc cancels the download"))
		return b.String()
	}

	switch {
	case t.cancelled:
		b.WriteString("\n" + p.muted.Render("esc to close"))
	case t.err != nil:
		b.WriteString("\n" + p.danger.Render(smbclient.Describe(t.err)) + "\n")
		b.WriteString(p.muted.Render("Press i for details, esc to close."))
	case t.failed > 0 || t.skipped > 0:
		fmt.Fprintf(&b, "\nDownloaded %d of %d files (%s).", t.filesDone, t.filesTotal, formatSize(t.done))
		if t.failed > 0 {
			fmt.Fprintf(&b, " %d problem%s.", t.failed, plural(t.failed, "", "s"))
		}
		if t.skipped > 0 {
			fmt.Fprintf(&b, " %d special entr%s skipped.", t.skipped, plural(t.skipped, "y", "ies"))
		}
		b.WriteString("\n")
		for i, failure := range t.failures {
			if i >= 3 {
				break
			}
			b.WriteString(p.danger.Render(termtext.Clean("· "+failure)) + "\n")
		}
		if len(t.failures) > 3 {
			fmt.Fprintf(&b, "%s\n", p.muted.Render(fmt.Sprintf("… and %d more", len(t.failures)-3)))
		}
		b.WriteString("\n" + p.muted.Render("i for details · esc to close"))
	default:
		fmt.Fprintf(&b, "\nDownloaded %d of %d files (%s).\n", t.filesDone, t.filesTotal, formatSize(t.done))
		b.WriteString("\n" + p.muted.Render("esc or enter to close"))
	}
	return b.String()
}

// bar renders the progress bar without the percentage or sizes.
func (t *transferState) bar(width int, ratio float64) string {
	barWidth := width - 30
	if barWidth < 12 {
		barWidth = 12
	}
	if barWidth > 40 {
		barWidth = 40
	}
	filled := int(ratio * float64(barWidth))
	switch {
	case filled < 0:
		filled = 0
	case filled > barWidth:
		filled = barWidth
	}
	return t.theme.accent.Render(strings.Repeat("█", filled)) +
		t.theme.faint.Render(strings.Repeat("░", barWidth-filled))
}

// sizeLine formats the transferred and total byte counts.
func (t *transferState) sizeLine() string {
	size := formatSize(t.done)
	if t.total > 0 {
		size += " / " + formatSize(t.total)
	}
	return size
}

// rateSuffix formats the current transfer rate and, when known, an estimated time remaining.
func (t *transferState) rateSuffix() string {
	if t.rate <= 0 {
		return ""
	}
	suffix := "  " + formatRate(t.rate)
	if t.total > 0 && t.rate > 1 {
		remaining := float64(t.total-t.done) / t.rate
		if remaining > 0 {
			suffix += fmt.Sprintf("  ETA %s", formatDuration(remaining))
		}
	}
	return suffix
}

// formatDuration renders a number of seconds compactly as seconds or minutes and seconds.
func formatDuration(seconds float64) string {
	d := time.Duration(seconds * float64(time.Second))
	if d < time.Second {
		return "<1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	minutes := int(d.Minutes())
	secs := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm%02ds", minutes, secs)
}
