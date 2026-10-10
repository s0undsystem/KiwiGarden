// Package sanitize cleans strings that came from receivers or the directory
// before they reach the browser or a log line.
package sanitize

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Text returns s with invalid UTF-8 replaced, every control (Cc) and format
// (Cf) rune removed, noncharacters removed, runs of whitespace collapsed to
// one space, surrounding whitespace trimmed, and the result truncated to at
// most max runes.
//
// Cf covers the bidi overrides and isolates (U+202A..U+202E, U+2066..U+2069,
// U+200E, U+200F, U+061C), zero-width characters, the BOM, soft hyphen and
// the invisible separators (U+2063) seen in the live directory.
func Text(s string, max int) string {
	if max <= 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(min(len(s), max*2))
	n := 0
	space := false
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		if r == utf8.RuneError && size == 1 {
			r = '�'
		}
		switch {
		case r == ' ', r == '\t', r == '\n', r == '\r', r == '\v', r == '\f', unicode.Is(unicode.Zs, r):
			space = true
			continue
		case unicode.Is(unicode.Cc, r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Co, r), unicode.Is(unicode.Cs, r):
			// NEL (U+0085) lands here, as a control, not as whitespace.
			continue
		case unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			space = true
			continue
		case isNoncharacter(r):
			continue
		}
		if space && n > 0 {
			if n+1 > max {
				break
			}
			b.WriteByte(' ')
			n++
		}
		space = false
		if n+1 > max {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimRight(b.String(), " ")
}

func isNoncharacter(r rune) bool {
	if r >= 0xFDD0 && r <= 0xFDEF {
		return true
	}
	return r&0xFFFE == 0xFFFE && r <= unicode.MaxRune
}

// ForLog prepares an untrusted string for a log line: sanitised, capped at
// max runes and quoted so that anything surprising left over is escaped.
func ForLog(s string, max int) string {
	return strconv.Quote(Text(s, max))
}
