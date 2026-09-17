package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// slowHandler is a server whose one handler blocks until the test lets it
// finish, and announces when it has started. Both halves matter: the
// announcement is what lets a test know the request is genuinely in flight
// before the drain begins, with no sleep and no race.
func slowHandler(started chan<- struct{}, release <-chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusOK)
	})
}

// startServer serves h on an ephemeral port and returns the server, the
// base URL to reach it, and a channel carrying Serve's error.
func startServer(t *testing.T, h http.Handler) (*http.Server, string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	srv := &http.Server{Handler: h}
	serveErr := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()
	return srv, "http://" + ln.Addr().String(), serveErr
}

// The property a graceful shutdown exists for: a request that has already
// started still gets its response, even though the signal has arrived and
// the listener has stopped accepting new ones.
//
// This is what a SIGTERM from `docker stop` or a rolling deploy does to a
// deployment, and the alternative — the process dying mid-request — is a
// password change that updated the hash but never revoked the session, or
// a client told the connection was closed with no reason.
func TestShutdownDrainsAnInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	srv, baseURL, serveErr := startServer(t, slowHandler(started, release))

	response := make(chan int, 1)
	go func() {
		resp, err := http.Get(baseURL)
		if err != nil {
			// A drain that dropped the connection shows up here rather
			// than as a status code, which is the failure this test is
			// for.
			response <- 0
			return
		}
		defer resp.Body.Close()
		response <- resp.StatusCode
	}()

	// Wait for the handler to be running before draining, so this is a
	// genuine in-flight request rather than a race against the client.
	<-started

	drained := make(chan error, 1)
	go func() { drained <- drain(srv, 5*time.Second) }()

	// The drain must still be waiting at this point — that it is not
	// finished before the handler is released is half the assertion.
	select {
	case err := <-drained:
		t.Fatalf("drain returned %v before the in-flight request finished", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	if err := <-drained; err != nil {
		t.Fatalf("drain failed with a request that was willing to finish: %v", err)
	}
	if code := <-response; code != http.StatusOK {
		t.Errorf("in-flight request returned %d, want 200 — a drained request must still be answered", code)
	}
	if err := <-serveErr; err != nil {
		t.Errorf("Serve returned %v after a clean shutdown, want nil", err)
	}

	// And the listener really is closed: the drain is supposed to stop
	// accepting, not just stop answering.
	if _, err := http.Get(baseURL); err == nil {
		t.Error("the server still accepts connections after a drain")
	}
}

// The other half of the contract: a request that will not finish does not
// hold the process open forever. A drain with no bound is a deploy that
// hangs until somebody kills it, which is worse than a cut-off request
// because it needs a human.
func TestShutdownGivesUpOnARequestThatWillNotFinish(t *testing.T) {
	started := make(chan struct{})
	// Never closed: this handler is the wedged client the timeout exists
	// for. It is still running when the test ends, which is fine — the
	// goroutine belongs to the test binary, not to a process that is
	// trying to exit.
	release := make(chan struct{})
	defer close(release)

	srv, baseURL, _ := startServer(t, slowHandler(started, release))

	go func() {
		resp, err := http.Get(baseURL)
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-started

	begin := time.Now()
	err := drain(srv, 100*time.Millisecond)
	elapsed := time.Since(begin)

	if err == nil {
		t.Fatal("drain returned nil with a request that could not finish")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("drain error = %v, want it to wrap context.DeadlineExceeded", err)
	}
	// The message names the wait, because the operator reading it is
	// looking at a deploy that took longer than expected and needs to know
	// which bound was hit.
	if want := "100ms"; !strings.Contains(err.Error(), want) {
		t.Errorf("drain error = %q, want it to name the %s wait", err, want)
	}
	if elapsed > 2*time.Second {
		t.Errorf("drain took %s to give up on a 100ms bound", elapsed)
	}
}

// drain is not the only way this server stops. A listener that fails on its
// own — a closed socket, a descriptor limit — has nothing in flight to
// drain, and Serve's error is what says so. The test pins that the error
// survives the ErrServerClosed translation rather than being swallowed
// into a nil.
func TestServeErrorIsReportedRatherThanDrained(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	srv := &http.Server{Handler: http.NotFoundHandler()}
	serveErr := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	// Closing the listener behind Serve is the failure being simulated.
	ln.Close()

	select {
	case err := <-serveErr:
		if err == nil {
			t.Fatal("a closed listener produced a nil error; ErrServerClosed is being translated too eagerly")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after its listener was closed")
	}
}
