// Package hostmatch matches host names against a small list of patterns: an
// exact name, a leading "*." wildcard that stands for one or more labels, or
// the bare "*" that names every host. It backs the passthrough list, where the
// same rule has to apply whether a host came from a CLI flag or a policy file.
//
// "*" is deliberately explicit: it turns a scan into a discovery run that
// relays everything and tests nothing, which is sometimes the only way to see
// which hosts an app contacts when its very first connection is pinned. A
// malformed wildcard ("*.", "api.*.example") is an error rather than a guess,
// so a typo can never silently widen the list.
package hostmatch

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// wildcardPrefix is the suffix wildcard form: a leading "*." standing for one
// or more labels.
const wildcardPrefix = "*."

// All is the pattern that names every host.
const All = "*"

// errWildcardPlacement explains the only wildcard forms accepted.
var errWildcardPlacement = errors.New(`wildcard is allowed only as a leading "*." or as the bare "*"`)

// Matcher holds normalized patterns. The zero value and a nil *Matcher match
// nothing.
type Matcher struct {
	all      bool
	exact    map[string]struct{}
	suffixes []string // Each as ".example.com": the part after the "*".
	patterns []string
}

// New builds a Matcher from patterns. Matching is case-insensitive and ignores
// a trailing dot. A pattern is an exact host, "*.<suffix>" (which matches
// "a.<suffix>" and "a.b.<suffix>" but not "<suffix>" itself), or [All]. An
// empty pattern, a wildcard anywhere but the front, or "*." with no suffix is
// an error.
func New(patterns ...string) (*Matcher, error) {
	m := &Matcher{exact: make(map[string]struct{})}
	for _, raw := range patterns {
		// Checked before normalization strips the trailing dot, which would
		// otherwise turn a suffix-less "*." into the bare "*".
		if strings.TrimSpace(raw) == wildcardPrefix {
			return nil, fmt.Errorf(`hostmatch: pattern %q has no suffix; use %q to name every host`, raw, All)
		}
		p := normalize(raw)
		if err := m.add(p); err != nil {
			return nil, fmt.Errorf("hostmatch: pattern %q: %w", raw, err)
		}
		m.patterns = append(m.patterns, p)
	}
	sort.Strings(m.patterns)
	return m, nil
}

// add validates one normalized pattern and files it.
func (m *Matcher) add(p string) error {
	switch {
	case p == "":
		return errors.New("empty pattern")
	case p == All:
		m.all = true
	case strings.HasPrefix(p, wildcardPrefix):
		suffix := p[len(wildcardPrefix)-1:] // Keep the dot: ".example.com".
		if strings.Contains(suffix, "*") {
			return errWildcardPlacement
		}
		m.suffixes = append(m.suffixes, suffix)
	case strings.Contains(p, "*"):
		return errWildcardPlacement
	default:
		m.exact[p] = struct{}{}
	}
	return nil
}

// Match reports whether host is named by one of the patterns.
func (m *Matcher) Match(host string) bool {
	if m == nil {
		return false
	}
	h := normalize(host)
	if h == "" {
		return false
	}
	if m.all {
		return true
	}
	if _, ok := m.exact[h]; ok {
		return true
	}
	for _, suffix := range m.suffixes {
		if len(h) > len(suffix) && strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

// MatchesAll reports whether the patterns include [All], so a caller can warn
// that every host will match.
func (m *Matcher) MatchesAll() bool { return m != nil && m.all }

// Empty reports whether the matcher has no patterns, so a caller can leave the
// passthrough machinery off entirely.
func (m *Matcher) Empty() bool { return m == nil || len(m.patterns) == 0 }

// Patterns returns the normalized patterns, sorted, for logs and reports.
func (m *Matcher) Patterns() []string {
	if m == nil {
		return nil
	}
	return append([]string(nil), m.patterns...)
}

// normalize lower-cases a name and drops surrounding space and a trailing dot.
func normalize(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
