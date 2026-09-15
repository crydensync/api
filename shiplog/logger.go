package shiplog

import (
	"context"
	"log"
	"time"

	"github.com/crydensync/cryden/v2/logger"
)

// DefaultTimeout bounds one insert. The write happens on the goroutine
// that logged, which is the request path, so this is the most a single
// wedged insert may add to a request — and it is per record, which is why
// the value is small: a request that logs twenty records while the
// database is unreachable spends twenty timeouts, and the level filter in
// front of the sink is what keeps that from being thirty.
const DefaultTimeout = 2 * time.Second

// Logger is the logger.Logger implementation: it writes every record it
// is handed into the Store.
//
// It implements logger.ContextLogger as well as logger.Logger, which is
// the difference between knowing which request a record came from and
// not. cryden calls Log in preference to the four bare methods when the
// Logger it holds has it — and the MultiLogger it holds here always does
// — so the context of the call being served reaches this sink. Nothing
// reads it today: the insert carries no request id, because a trace key
// belongs to the host app and this repo has not defined one. It is taken
// anyway rather than discarded, because the alternative shape (implement
// only the four methods) makes the context unreachable by construction,
// and a sink that cannot see the request can never correlate with it.
//
// Nothing here panics or returns an error upward, because
// logger.Logger's contract has no room for either. A failed insert is
// reported to Log and the record is lost: a log that could fail the
// operation it was describing would be worse than a log with a hole in
// it. Inside a MultiLogger the hole is survivable — the console copy
// still happened — which is exactly why the composition puts this sink
// beside the console one rather than instead of it.
type Logger struct {
	// Store is where records go. A nil Store makes this sink silent, and
	// is checked rather than assumed because a nil *Logger inside a
	// logger.Logger interface is not a nil interface: NewMultiLogger's
	// own doc comment names that trap, and the one setting that produces
	// it here is CLOUD_LOGGING being off.
	Store Store

	// Timeout bounds one insert. Zero means DefaultTimeout.
	Timeout time.Duration

	// Errors receives a line per failed insert. Nil means silent, which is
	// what a test wants and what a deployment that would rather not have a
	// second failure mode on its stderr can ask for.
	//
	// Named Errors rather than Log because this type has to implement
	// logger.ContextLogger, whose method is Log — a field and a method
	// cannot share a name, and the method is the one the interface
	// dictates. The webhook worker's field of the same purpose is Log
	// only because no such method forced its hand.
	Errors *log.Logger
}

var _ logger.ContextLogger = (*Logger)(nil)

// NewLogger builds a sink over store with the default timeout.
func NewLogger(store Store) *Logger {
	return &Logger{Store: store}
}

// Log records one event. A nil ctx is treated as context.Background(), as
// logger.ContextLogger requires of every implementation: the four bare
// methods have no context to give and a wrapper standing in for one of
// them passes exactly that.
func (l *Logger) Log(ctx context.Context, level logger.Level, msg string, fields map[string]string) {
	if l == nil || l.Store == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	timeout := l.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	// context.WithoutCancel, for the same reason the webhook sender uses
	// it: by the time a slow insert runs, the request that logged may be
	// gone, and a record about a request is most worth having exactly
	// when the request failed. The timeout is what stops that from
	// turning into an unbounded write.
	insertCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()

	err := l.Store.Insert(insertCtx, Entry{
		Level:   level,
		Message: msg,
		Fields:  fields,
		Sink:    SinkName,
	})
	if err != nil {
		l.logf("shiplog: recording a %s record (%q): %v", level, msg, err)
	}
}

func (l *Logger) Debug(msg string, fields map[string]string) {
	l.Log(context.Background(), logger.LevelDebug, msg, fields)
}

func (l *Logger) Info(msg string, fields map[string]string) {
	l.Log(context.Background(), logger.LevelInfo, msg, fields)
}

func (l *Logger) Warn(msg string, fields map[string]string) {
	l.Log(context.Background(), logger.LevelWarn, msg, fields)
}

func (l *Logger) Error(msg string, fields map[string]string) {
	l.Log(context.Background(), logger.LevelError, msg, fields)
}

func (l *Logger) logf(format string, args ...any) {
	if l.Errors != nil {
		l.Errors.Printf(format, args...)
	}
}
