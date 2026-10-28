package hostmatch_test

import (
	"slices"
	"testing"

	"github.com/yinkoshield/pinscan/internal/hostmatch"
)

func TestMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		patterns []string
		host     string
		want     bool
	}{
		{"exact", []string{"api.example.com"}, "api.example.com", true},
		{"exact is case-insensitive", []string{"API.Example.com"}, "api.example.COM", true},
		{"exact ignores a trailing dot", []string{"api.example.com"}, "api.example.com.", true},
		{"exact does not match a subdomain", []string{"example.com"}, "api.example.com", false},
		{"exact does not match a parent", []string{"api.example.com"}, "example.com", false},
		{"exact does not match a suffix overlap", []string{"example.com"}, "notexample.com", false},
		{"wildcard matches one label", []string{"*.example.com"}, "api.example.com", true},
		{"wildcard matches several labels", []string{"*.example.com"}, "login.eu.example.com", true},
		{"wildcard does not match the bare suffix", []string{"*.example.com"}, "example.com", false},
		{"wildcard does not match a suffix overlap", []string{"*.example.com"}, "notexample.com", false},
		{"wildcard is case-insensitive", []string{"*.Example.COM"}, "API.example.com", true},
		{"several patterns, second matches", []string{"a.example", "*.b.example"}, "x.b.example", true},
		{"several patterns, none match", []string{"a.example", "*.b.example"}, "b.example", false},
		{"no patterns", nil, "api.example.com", false},
		{"empty host", []string{"*.example.com"}, "", false},
		{"all matches any host", []string{"*"}, "api.example.com", true},
		{"all matches a bare label", []string{"*"}, "localhost", true},
		{"all alongside others", []string{"a.example", "*"}, "b.example", true},
		{"all does not match an empty host", []string{"*"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, err := hostmatch.New(tt.patterns...)
			if err != nil {
				t.Fatalf("New(%q): %v", tt.patterns, err)
			}
			if got := m.Match(tt.host); got != tt.want {
				t.Errorf("New(%q).Match(%q) = %v, want %v", tt.patterns, tt.host, got, tt.want)
			}
		})
	}
}

func TestNewRejectsBadPatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
	}{
		{"star dot has no suffix", "*."},
		{"star dot with spaces", "  *.  "},
		{"empty", ""},
		{"only spaces", "   "},
		{"only a dot", "."},
		{"wildcard in the middle", "api.*.example.com"},
		{"wildcard at the end", "api.example.*"},
		{"partial-label wildcard", "*api.example.com"},
		{"two wildcards", "*.*.example.com"},
		{"double star", "**"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := hostmatch.New(tt.pattern); err == nil {
				t.Fatalf("New(%q) = nil error, want an error", tt.pattern)
			}
		})
	}
}

func TestNewRejectsOneBadPatternAmongGood(t *testing.T) {
	t.Parallel()

	if _, err := hostmatch.New("api.example.com", "*.", "*.b.example"); err == nil {
		t.Error("New with a malformed wildcard among valid patterns = nil error, want an error")
	}
}

func TestMatchesAll(t *testing.T) {
	t.Parallel()

	all, err := hostmatch.New("api.example.com", hostmatch.All)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !all.MatchesAll() {
		t.Error("MatchesAll() = false with a bare * among the patterns")
	}
	some, err := hostmatch.New("api.example.com", "*.b.example")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if some.MatchesAll() {
		t.Error("MatchesAll() = true without a bare *")
	}
	var nilMatcher *hostmatch.Matcher
	if nilMatcher.MatchesAll() {
		t.Error("a nil matcher reports MatchesAll")
	}
}

func TestPatternsAndEmpty(t *testing.T) {
	t.Parallel()

	m, err := hostmatch.New("B.example", "*.A.Example.", "c.example")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	want := []string{"*.a.example", "b.example", "c.example"}
	if got := m.Patterns(); !slices.Equal(got, want) {
		t.Errorf("Patterns() = %q, want normalized and sorted %q", got, want)
	}
	if m.Empty() {
		t.Error("Empty() = true for a matcher with patterns")
	}

	empty, err := hostmatch.New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if !empty.Empty() {
		t.Error("Empty() = false for a matcher with no patterns")
	}
	if len(empty.Patterns()) != 0 {
		t.Errorf("Patterns() = %q for an empty matcher", empty.Patterns())
	}
}

func TestNilMatcherMatchesNothing(t *testing.T) {
	t.Parallel()

	var m *hostmatch.Matcher
	if m.Match("api.example.com") {
		t.Error("a nil matcher matched a host")
	}
	if !m.Empty() {
		t.Error("a nil matcher is not Empty")
	}
	if m.Patterns() != nil {
		t.Error("a nil matcher has patterns")
	}
}
