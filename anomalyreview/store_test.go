package anomalyreview

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const (
	eventA = "01a0a4ce-5453-78d3-9126-52268da8da51"
	eventB = "01a0a4ce-5453-78d3-9126-52268da8da52"
)

func reviewFixture() *MemoryStore {
	s := NewMemoryStore()
	s.RegisterEvents(eventA, eventB)
	return s
}

// The rule has to be exact: a status this api does not define must not be
// storable, and "Confirmed" is not "confirmed".
func TestValidateStatusAcceptsExactlyTheThreeDefinedStatuses(t *testing.T) {
	for _, status := range Statuses() {
		if err := ValidateStatus(status); err != nil {
			t.Errorf("ValidateStatus(%q) = %v, want nil", status, err)
		}
	}

	for _, status := range []Status{"", "Confirmed", "DISMISSED", "reviewed", "resolved", "deleted", "true"} {
		err := ValidateStatus(status)
		if !errors.Is(err, ErrInvalidStatus) {
			t.Errorf("ValidateStatus(%q) = %v, want ErrInvalidStatus", status, err)
		}
		// The message names the offending value and the permitted ones,
		// so an operator reading it does not have to guess.
		if err != nil && !strings.Contains(err.Error(), string(status)) {
			t.Errorf("ValidateStatus(%q) message = %q, want it to name the value", status, err)
		}
	}
}

func TestSetRecordsAReviewAndReadsItBack(t *testing.T) {
	s := reviewFixture()
	ctx := context.Background()

	stored, err := s.Set(ctx, eventA, StatusConfirmed, "matches the report from the customer", eventB)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if stored.EventID != eventA || stored.Status != StatusConfirmed {
		t.Errorf("stored = %+v, want a confirmed review of %s", stored, eventA)
	}
	if stored.UpdatedAt.IsZero() {
		t.Error("stored.UpdatedAt is zero — the store assigns it, the caller does not")
	}

	reviews, err := s.StatusesFor(ctx, []string{eventA, eventB})
	if err != nil {
		t.Fatalf("StatusesFor: %v", err)
	}
	if len(reviews) != 1 {
		t.Fatalf("reviews = %v, want only the one event that has a review", reviews)
	}
	got := reviews[eventA]
	if got.Status != StatusConfirmed || got.Note != "matches the report from the customer" || got.ReviewerID != eventB {
		t.Errorf("review = %+v, want the note and reviewer to survive the round trip", got)
	}
}

// A second decision replaces the first rather than accumulating rows.
func TestSetReplacesThePreviousDecision(t *testing.T) {
	s := reviewFixture()
	ctx := context.Background()

	if _, err := s.Set(ctx, eventA, StatusConfirmed, "", eventB); err != nil {
		t.Fatalf("Set (confirmed): %v", err)
	}
	second, err := s.Set(ctx, eventA, StatusDismissed, "false positive, new laptop", eventB)
	if err != nil {
		t.Fatalf("Set (dismissed): %v", err)
	}
	if second.Status != StatusDismissed {
		t.Errorf("status = %q, want the second decision to win", second.Status)
	}
	if s.Len() != 1 {
		t.Errorf("stored reviews = %d, want 1 — a change of mind is not a second row", s.Len())
	}
}

// The property the whole table exists for: withdrawing a judgement stores
// a status, it does not delete the row. If this ever becomes a delete,
// the record of who looked at the event and when is gone.
func TestWithdrawingAReviewKeepsTheRow(t *testing.T) {
	s := reviewFixture()
	ctx := context.Background()

	if _, err := s.Set(ctx, eventA, StatusConfirmed, "looked real", eventB); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := s.Set(ctx, eventA, StatusUnreviewed, "", eventB); err != nil {
		t.Fatalf("Set (withdraw): %v", err)
	}

	if s.Len() != 1 {
		t.Fatalf("stored reviews = %d, want the row to survive being set back to unreviewed", s.Len())
	}
	status, ok := s.Status(eventA)
	if !ok {
		t.Fatal("the row was deleted — unreviewed is a status, not an absence")
	}
	if status != StatusUnreviewed {
		t.Errorf("status = %q, want %q", status, StatusUnreviewed)
	}
}

// The Postgres store refuses this through the foreign key on
// audit_events. The double has to refuse it too, or a handler test would
// assert a 404 that production never produces.
func TestSetRefusesAnEventThatDoesNotExist(t *testing.T) {
	s := reviewFixture()

	_, err := s.Set(context.Background(), "01a0a4ce-5453-78d3-9126-000000000000", StatusConfirmed, "", eventB)
	if !errors.Is(err, ErrNoSuchEvent) {
		t.Fatalf("error = %v, want ErrNoSuchEvent", err)
	}
	if s.Len() != 0 {
		t.Errorf("stored reviews = %d, want nothing written for an event that does not exist", s.Len())
	}
}

// A refused write is refused rather than written-and-reported, which is
// the difference between a rule and a warning.
func TestRefusedWritesStoreNothing(t *testing.T) {
	s := reviewFixture()
	ctx := context.Background()

	if _, err := s.Set(ctx, eventA, Status("resolved"), "", eventB); !errors.Is(err, ErrInvalidStatus) {
		t.Errorf("error = %v, want ErrInvalidStatus", err)
	}
	if _, err := s.Set(ctx, eventA, StatusConfirmed, strings.Repeat("x", maxNoteLength+1), eventB); !errors.Is(err, ErrNoteTooLong) {
		t.Errorf("error = %v, want ErrNoteTooLong", err)
	}

	if s.Len() != 0 {
		t.Errorf("stored reviews = %d, want none", s.Len())
	}
}

// Exactly at the bound is allowed: the limit is a limit, not a reason to
// be one short of it.
func TestANoteAtTheLengthLimitIsAccepted(t *testing.T) {
	s := reviewFixture()

	note := strings.Repeat("x", maxNoteLength)
	if _, err := s.Set(context.Background(), eventA, StatusConfirmed, note, eventB); err != nil {
		t.Fatalf("Set with a %d-character note: %v", maxNoteLength, err)
	}
}

// The list endpoint hands over a page of event ids and gets back only
// those that have reviews. An empty map rather than nil, so a caller can
// range over it without a nil check and a JSON response renders {} not
// null — the same contract usermeta.Store.AllFor keeps.
func TestStatusesForReturnsOnlyTheIdsAskedAbout(t *testing.T) {
	s := reviewFixture()
	ctx := context.Background()

	if _, err := s.Set(ctx, eventA, StatusDismissed, "", eventB); err != nil {
		t.Fatalf("Set: %v", err)
	}

	reviews, err := s.StatusesFor(ctx, []string{eventB})
	if err != nil {
		t.Fatalf("StatusesFor: %v", err)
	}
	if len(reviews) != 0 {
		t.Errorf("reviews = %v, want nothing — %s was not asked about", reviews, eventA)
	}

	empty, err := s.StatusesFor(ctx, nil)
	if err != nil {
		t.Fatalf("StatusesFor(nil): %v", err)
	}
	if empty == nil {
		t.Error("StatusesFor(nil) returned nil, want an empty non-nil map")
	}
	if len(empty) != 0 {
		t.Errorf("StatusesFor(nil) = %v, want empty", empty)
	}
}
