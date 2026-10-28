package proxy

import (
	"sort"
	"sync"

	"github.com/yinkoshield/pinscan/internal/classify"
)

// Observation is a host's recorded result for one wave: the strongest outcome
// seen, the reason behind it, how many connection attempts backed it, and
// whether attempts disagreed decisively (both accepted and genuinely rejected).
type Observation struct {
	Outcome  classify.WaveOutcome
	Reason   string
	Attempts int
	Conflict bool
}

// hostRecord is the Observer's internal, mutable per-host state.
type hostRecord struct {
	outcome     classify.WaveOutcome
	reason      string
	attempts    int
	sawAccepted bool
	sawRejected bool
}

// Observer records, per host, the strongest outcome seen during a wave, the
// reason, and how many attempts backed it. It is safe for concurrent use.
//
// A host may open several connections in one wave; the Observer keeps the
// highest-priority outcome across them (see [outcomePriority]): an acceptance
// anywhere wins, then a genuine rejection, then an ambiguous signal. It also
// counts attempts and flags a conflict when attempts both accepted and
// genuinely rejected the forged certificate — evidence a verdict should be
// trusted less.
type Observer struct {
	mu     sync.Mutex
	byHost map[string]hostRecord
}

// NewObserver returns an empty Observer.
func NewObserver() *Observer {
	return &Observer{byHost: make(map[string]hostRecord)}
}

// outcomePriority ranks outcomes so the strongest signal is retained.
func outcomePriority(o classify.WaveOutcome) int {
	switch o {
	case classify.Accepted:
		return 3
	case classify.Rejected:
		return 2
	case classify.Ambiguous:
		return 1
	case classify.NotObserved:
		return 0
	default:
		return 0
	}
}

// Record notes an outcome and reason for host, keeping the highest-priority
// outcome seen so far and counting the attempt.
func (o *Observer) Record(host string, outcome classify.WaveOutcome, reason string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	r := o.byHost[host]
	r.attempts++
	switch outcome {
	case classify.Accepted:
		r.sawAccepted = true
	case classify.Rejected:
		r.sawRejected = true
	case classify.Ambiguous, classify.NotObserved:
		// Neither is a decisive signal; it cannot create a conflict.
	}
	if outcomePriority(outcome) > outcomePriority(r.outcome) {
		r.outcome = outcome
		r.reason = reason
	}
	o.byHost[host] = r
}

// Outcome returns the recorded outcome for host, or [classify.NotObserved].
func (o *Observer) Outcome(host string) classify.WaveOutcome {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.byHost[host].outcome
}

// Observation returns the full recorded observation for host (zero value if the
// host was never seen).
func (o *Observer) Observation(host string) Observation {
	o.mu.Lock()
	defer o.mu.Unlock()
	r := o.byHost[host]
	return Observation{
		Outcome:  r.outcome,
		Reason:   r.reason,
		Attempts: r.attempts,
		Conflict: r.sawAccepted && r.sawRejected,
	}
}

// Hosts returns the observed hosts in sorted order.
func (o *Observer) Hosts() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	hosts := make([]string, 0, len(o.byHost))
	for host := range o.byHost {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}
