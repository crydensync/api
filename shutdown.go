package main

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// shutdownDrainTimeout bounds how long a shutdown waits for the requests
// already in flight to finish.
//
// Thirty seconds is a number chosen rather than derived, so here is what
// it is trading. Too short and a slow request is cut off mid-write — a
// password change that has updated the hash but not yet revoked the
// session, say. Too long and a deploy sits waiting on one wedged client
// that will never read its response. Thirty seconds is past every
// handler's own work here (the slowest is the read-only-database check on
// PUT /v1/admin/settings/database-provider, which opens a connection to
// another server) and short enough that a rolling deploy is not held up.
//
// It is a constant rather than an env var because it is a property of
// this API's handlers, not of a deployment: nothing about a particular
// install makes a request here take longer. If that stops being true —
// the ask-ai widget's questions take as long as a model takes, and today
// that is bounded by the provider's own client timeout rather than by
// anything here — it becomes a knob.
const shutdownDrainTimeout = 30 * time.Second

// drain stops the server accepting new connections and waits up to
// timeout for the ones already in flight to finish.
//
// It is the whole of what a graceful shutdown does to the HTTP side, kept
// out of main so it can be tested: the property worth pinning is that a
// request which has already started still gets its response after the
// signal arrives, and that a request which refuses to finish does not
// hold the process open forever.
func drain(srv *http.Server, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		// Shutdown has given up, which leaves the connections it was
		// waiting on open. Close is what actually releases the listener
		// and the sockets — without it the process can still exit, but
		// nothing that was waiting on this server is told so. Its error is
		// dropped deliberately: the interesting failure is the timeout,
		// and Close's own error is almost always the same one.
		_ = srv.Close()
		return fmt.Errorf("draining in-flight requests (waited %s): %w", timeout, err)
	}
	return nil
}
