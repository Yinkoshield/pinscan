package selftest

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestPostureCountMatchesCodeAndREADME stops the documented posture count from
// drifting: the README once said "five" while the self-test ran six.
func TestPostureCountMatchesCodeAndREADME(t *testing.T) {
	t.Parallel()

	if n := len(postures()); n != PostureCount {
		t.Fatalf("postures() has %d entries, PostureCount is %d: update the constant and the README", n, PostureCount)
	}

	words := map[int]string{4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten"}
	word, ok := words[PostureCount]
	if !ok {
		t.Fatalf("no word for PostureCount %d; extend the table", PostureCount)
	}
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	want := fmt.Sprintf("%s in-process clients", word)
	if !strings.Contains(string(readme), want) {
		t.Errorf("README does not say %q; the self-test runs %d postures", want, PostureCount)
	}
}
