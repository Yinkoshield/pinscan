package proxy_test

import (
	"slices"
	"testing"

	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/proxy"
)

func TestObserverUnseenHostIsNotObserved(t *testing.T) {
	t.Parallel()

	obs := proxy.NewObserver()
	if got := obs.Outcome("unseen.example.com"); got != classify.NotObserved {
		t.Errorf("unseen host = %s, want not-observed", got)
	}
}

func TestObserverRecordsOutcomeAndReason(t *testing.T) {
	t.Parallel()

	obs := proxy.NewObserver()
	obs.Record("a.example.com", classify.Rejected, "tls_alert_bad_certificate")
	if got := obs.Outcome("a.example.com"); got != classify.Rejected {
		t.Errorf("recorded outcome = %s, want rejected", got)
	}
	if got := obs.Observation("a.example.com").Reason; got != "tls_alert_bad_certificate" {
		t.Errorf("recorded reason = %q, want tls_alert_bad_certificate", got)
	}
}

func TestObserverAcceptedIsSticky(t *testing.T) {
	t.Parallel()

	accepted := proxy.NewObserver()
	accepted.Record("h", classify.Accepted, "request_observed")
	accepted.Record("h", classify.Rejected, "tls_alert_bad_certificate") // must not downgrade.
	if got := accepted.Outcome("h"); got != classify.Accepted {
		t.Errorf("accept then reject = %s, want accepted", got)
	}

	upgraded := proxy.NewObserver()
	upgraded.Record("h", classify.Rejected, "tls_alert_bad_certificate")
	upgraded.Record("h", classify.Accepted, "request_observed") // must upgrade.
	if got := upgraded.Outcome("h"); got != classify.Accepted {
		t.Errorf("reject then accept = %s, want accepted", got)
	}
}

func TestObserverRejectedBeatsAmbiguous(t *testing.T) {
	t.Parallel()

	// A genuine certificate rejection on one connection must not be masked by an
	// ambiguous (reset/timeout) signal on another.
	obs := proxy.NewObserver()
	obs.Record("h", classify.Ambiguous, "transport_error")
	obs.Record("h", classify.Rejected, "tls_alert_unknown_ca")
	if got := obs.Outcome("h"); got != classify.Rejected {
		t.Errorf("ambiguous then rejected = %s, want rejected", got)
	}
	if got := obs.Observation("h").Reason; got != "tls_alert_unknown_ca" {
		t.Errorf("reason = %q, want tls_alert_unknown_ca", got)
	}

	// An ambiguous signal must not downgrade a prior genuine rejection.
	obs.Record("h", classify.Ambiguous, "timeout")
	if got := obs.Outcome("h"); got != classify.Rejected {
		t.Errorf("rejected then ambiguous = %s, want rejected (no downgrade)", got)
	}
}

func TestObserverCountsAttempts(t *testing.T) {
	t.Parallel()

	obs := proxy.NewObserver()
	obs.Record("h", classify.Rejected, "tls_alert_bad_certificate")
	obs.Record("h", classify.Rejected, "tls_alert_bad_certificate")
	obs.Record("h", classify.Ambiguous, "timeout")
	o := obs.Observation("h")
	if o.Attempts != 3 {
		t.Errorf("Attempts = %d, want 3", o.Attempts)
	}
	if o.Outcome != classify.Rejected {
		t.Errorf("Outcome = %s, want rejected (strongest)", o.Outcome)
	}
	if o.Conflict {
		t.Error("Conflict = true, want false (no acceptance seen)")
	}
}

func TestObserverFlagsConflict(t *testing.T) {
	t.Parallel()

	// Some connections accepted the forged cert, another genuinely rejected it:
	// contradictory decisive signals, which must lower confidence downstream.
	obs := proxy.NewObserver()
	obs.Record("h", classify.Accepted, "request_observed")
	obs.Record("h", classify.Rejected, "tls_alert_bad_certificate")
	o := obs.Observation("h")
	if !o.Conflict {
		t.Error("Conflict = false, want true (accepted and rejected both seen)")
	}
	if o.Attempts != 2 {
		t.Errorf("Attempts = %d, want 2", o.Attempts)
	}
}

func TestObserverHostsSorted(t *testing.T) {
	t.Parallel()

	obs := proxy.NewObserver()
	obs.Record("b.example.com", classify.Rejected, "tls_alert_bad_certificate")
	obs.Record("a.example.com", classify.Accepted, "request_observed")
	if got, want := obs.Hosts(), []string{"a.example.com", "b.example.com"}; !slices.Equal(got, want) {
		t.Errorf("Hosts() = %v, want %v", got, want)
	}
}
