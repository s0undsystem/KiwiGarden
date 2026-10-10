package sanitize

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestText(t *testing.T) {
	cases := []struct {
		name, in string
		max      int
		want     string
	}{
		{"plain", "Hello, World", 100, "Hello, World"},
		{"trim and collapse", "  a \t\n b   c  ", 100, "a b c"},
		{"control chars", "a\x00b\x1fc\x7fd", 100, "abcd"},
		{"c1 controls", "a\u0085b\u009fc", 100, "abc"},
		{"bidi override", "abc\u202Eevil\u202C", 100, "abcevil"},
		{"bidi isolates", "\u2066x\u2069\u200E\u200F\u061C", 100, "x"},
		{"zero width", "K​i‌w‍i⁠\xef\xbb\xbf", 100, "Kiwi"},
		{"invisible separator from live directory", "KiwiSDR 2 ⁣ GPS", 100, "KiwiSDR 2 GPS"},
		{"soft hyphen", "soft­hyphen", 100, "softhyphen"},
		{"invalid utf8", "a\xffb\xc0\xafc", 100, "a�b��c"},
		{"noncharacter", "a﷐b￾c￿d", 100, "abcd"},
		{"private use", "ab", 100, "ab"},
		{"emoji kept", "📡 GPS", 100, "📡 GPS"},
		{"truncate runes", "héllo wörld", 5, "héllo"},
		{"truncate at space", "ab cd", 3, "ab"},
		{"max zero", "abc", 0, ""},
		{"only spaces", "   \t ", 10, ""},
		{"cjk", "東京 日本", 10, "東京 日本"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Text(c.in, c.max)
			if got != c.want {
				t.Fatalf("Text(%q,%d) = %q, want %q", c.in, c.max, got, c.want)
			}
			if utf8.RuneCountInString(got) > c.max {
				t.Fatalf("result longer than max: %d runes", utf8.RuneCountInString(got))
			}
		})
	}
}

func TestForLog(t *testing.T) {
	// newline becomes a space, ESC is removed, result is quoted.
	if got, want := ForLog("name\n\x1b[31mred", 50), `"name [31mred"`; got != want {
		t.Fatalf("ForLog = %s, want %s", got, want)
	}
	if got := ForLog(strings.Repeat("x", 100), 5); got != `"xxxxx"` {
		t.Fatalf("ForLog truncation = %s", got)
	}
}

func FuzzText(f *testing.F) {
	for _, s := range []string{"", "abc", "\u202E", "\xff\xfe", "a b  c", strings.Repeat("x", 1000)} {
		f.Add(s, 50)
	}
	f.Fuzz(func(t *testing.T, s string, max int) {
		if max > 10000 {
			max = 10000
		}
		got := Text(s, max)
		if !utf8.ValidString(got) {
			t.Fatalf("invalid utf8 out: %q", got)
		}
		if max > 0 && utf8.RuneCountInString(got) > max {
			t.Fatalf("too long: %d > %d", utf8.RuneCountInString(got), max)
		}
		for _, r := range got {
			if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || (unicode.IsSpace(r) && r != ' ') {
				t.Fatalf("forbidden rune %U in %q", r, got)
			}
		}
		if strings.Contains(got, "  ") || strings.HasPrefix(got, " ") || strings.HasSuffix(got, " ") {
			t.Fatalf("whitespace not normalised: %q", got)
		}
	})
}
