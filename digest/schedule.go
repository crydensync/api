package digest

import (
	"context"
	"log"
	"time"
)

// Builder produces one digest for the scheduler to record. It returns an
// Entry with ID unset — the store assigns one, and the store's own
// zero-value rule fills in whatever timestamp the builder leaves alone.
//
// It is a function rather than a store interface because the thing being
// wrapped is cryden's DigestSince, which takes the engine and returns a
// string. Threading a whole engine through this package to call it would
// mean this package importing the engine to describe a seam the caller
// can close in three lines.
type Builder func(ctx context.Context) (Entry, error)

// Scheduler builds a digest on an interval and records each one.
//
// It is the only writer in this package, and it is a process component
// rather than anything a request can reach: no endpoint in this repo
// creates a digest run, so an operator cannot manufacture history
// through the API. That is the same shape the admin surface keeps
// everywhere else — see CLAUDE.md's hard rule.
type Scheduler struct {
	Store Store
	Build Builder

	// Interval is how long to wait between runs. Zero or negative means
	// there is no schedule, and Run returns immediately without starting
	// anything — main.go only constructs a Scheduler when
	// DIGEST_INTERVAL_HOURS asked for one, so a zero here is a wiring
	// mistake rather than a setting.
	Interval time.Duration

	// Log receives one line per failed run. Optional; a nil Log discards
	// them.
	//
	// Failures are logged and swallowed rather than returned: this runs in
	// its own goroutine with nobody to hand an error to, and a scheduler
	// that stopped on the first database blip would silently stop
	// producing digests for the rest of the process's life — the exact
	// failure a schedule exists to avoid.
	Log *log.Logger
}

// Run blocks until ctx is done, building and recording a digest once per
// Interval.
//
// The first run happens after a full Interval, not at startup. That is
// deliberate: the interval is the schedule, and a process that restarts
// more often than the interval elapses — a crashloop, a deploy pipeline,
// a developer's laptop — would otherwise manufacture one digest row per
// start. A history that grows with restarts rather than with time is not
// a history of anything.
//
// main.go hands this the context the shutdown signal cancels, so a SIGTERM
// stops it between runs. Nothing here needed to be stoppable for
// correctness — an interrupted run records nothing and the next interval
// builds another — but a build cut off halfway is worse than one that
// never started, because half a window in the history reads as a quiet
// week rather than as a missing one.
func (s *Scheduler) Run(ctx context.Context) {
	if s.Interval <= 0 || s.Store == nil || s.Build == nil {
		return
	}

	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

// runOnce builds one digest and records it, logging rather than returning
// any failure — see the Log field for why the loop must survive one.
func (s *Scheduler) runOnce(ctx context.Context) {
	entry, err := s.Build(ctx)
	if err != nil {
		s.logf("digest: building the scheduled digest failed: %v", err)
		return
	}

	// The zero-value rule stamps GeneratedAt and WindowEnd if the builder
	// left them; a builder that set neither still produces a readable row.
	saved, err := s.Store.Insert(ctx, entry)
	if err != nil {
		s.logf("digest: recording the scheduled digest failed: %v", err)
		return
	}
	s.logf("digest: recorded a scheduled digest covering %s to %s (run %d)",
		saved.WindowStart.UTC().Format(time.RFC3339), saved.WindowEnd.UTC().Format(time.RFC3339), saved.ID)
}

func (s *Scheduler) logf(format string, args ...any) {
	if s.Log == nil {
		return
	}
	s.Log.Printf(format, args...)
}
