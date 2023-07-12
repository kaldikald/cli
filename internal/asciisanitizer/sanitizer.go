// Package asciisanitizer implements an ASCII control character sanitizer for GitHub API responses so they can be
// safely displayed in the terminal. The GitHub API does not sanitize their responses for terminal display and will
// leave in unescaped ASCII control characters. These ASCII control characters will be interpreted by the terminal,
// this behaviour can be used maliciously as an attack vector, especially the ASCII control characters \u001B and \u009B.
package asciisanitizer

import (
	"bytes"
	"strings"

	"golang.org/x/text/transform"
)

// Sanitizer implements transform.Transformer interface.
type Sanitizer struct {
	addEscape bool
}

// Transform uses a sliding window algorithm to detect C0 and C1 control characters as they are read and replaces
// them with equivalent inert characters. Bytes that are not part of a control character are not modified.
// C0 control characters are encoded as six bytes, representing the unicode code point, ranging from \u0000 to \u001F.
// C1 control characters are encoded as two bytes, the first being 0xC2 and the second ranging from 0x80 to 0x9F.
func (t *Sanitizer) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	lSrc := len(src)
	lDst := len(dst)

	for nSrc < lSrc && nDst < lDst {
		var window []byte
		if nSrc+6 <= lSrc {
			window = src[nSrc : nSrc+6]
		} else if !atEOF {
			err = transform.ErrShortSrc
			return
		} else {
			window = src[nSrc : nSrc+2]
		}

		// Replace C1 control characters.
		if repl, found := mapC1ToCaret(window[:2]); found {
			if len(repl)+nDst > lDst {
				err = transform.ErrShortDst
				return
			}
			for j := 0; j < len(repl); j++ {
				dst[nDst] = repl[j]
				nDst++
			}
			nSrc += 2
			continue
		}

		// Replace C0 control characters.
		if repl, found := mapC0ToCaret(window); found {
			if t.addEscape {
				repl = append([]byte{'\\'}, repl...)
			}
			if len(repl)+nDst > lDst {
				err = transform.ErrShortDst
				return
			}
			for j := 0; j < len(repl); j++ {
				dst[nDst] = repl[j]
				nDst++
			}
			t.addEscape = false
			nSrc += 6
			continue
		}

		if window[0] == '\\' {
			t.addEscape = !t.addEscape
		} else {
			t.addEscape = false
		}

		dst[nDst] = src[nSrc]
		nDst++
		nSrc++
	}

	if nDst == lDst && nSrc != lSrc {
		err = transform.ErrShortDst
		return
	}

	return
}

// Reset resets the state and allows the Sanitizer to be reused.
func (t *Sanitizer) Reset() {
	t.addEscape = false
}

// mapC0ToCaret maps C0 control characters to their caret notation.
// C0 control characters are encoded as six bytes, representing the unicode code point, ranging from \u0000 to \u001F.
func mapC0ToCaret(b []byte) ([]byte, bool) {
	if len(b) != 6 {
		return b, false
	}
	if !bytes.HasPrefix(b, []byte(`\u00`)) {
		return b, false
	}
	m := map[string]string{
		`\u0000`: `^@`,
		`\u0001`: `^A`,
		`\u0002`: `^B`,
		`\u0003`: `^C`,
		`\u0004`: `^D`,
		`\u0005`: `^E`,
		`\u0006`: `^F`,
		`\u0007`: `^G`,
		`\u0008`: `^H`,
		`\u0009`: `^I`,
		`\u000a`: `^J`,
		`\u000b`: `^K`,
		`\u000c`: `^L`,
		`\u000d`: `^M`,
		`\u000e`: `^N`,
		`\u000f`: `^O`,
		`\u0010`: `^P`,
		`\u0011`: `^Q`,
		`\u0012`: `^R`,
		`\u0013`: `^S`,
		`\u0014`: `^T`,
		`\u0015`: `^U`,
		`\u0016`: `^V`,
		`\u0017`: `^W`,
		`\u0018`: `^X`,
		`\u0019`: `^Y`,
		`\u001a`: `^Z`,
		`\u001b`: `^[`,
		`\u001c`: `^\\`,
		`\u001d`: `^]`,
		`\u001e`: `^^`,
		`\u001f`: `^_`,
	}
	if c, ok := m[strings.ToLower(string(b))]; ok {
		return []byte(c), true
	}
	return b, false
}

// mapC1ToCaret maps C1 control characters to their caret notation.
// C1 control characters are encoded as two bytes, the first being 0xC2 and the second ranging from 0x80 to 0x9F.
func mapC1ToCaret(b []byte) ([]byte, bool) {
	if len(b) != 2 {
		return b, false
	}
	if b[0] != 0xC2 {
		return b, false
	}
	m := map[byte]string{
		128: `^@`,
		129: `^A`,
		130: `^B`,
		131: `^C`,
		132: `^D`,
		133: `^E`,
		134: `^F`,
		135: `^G`,
		136: `^H`,
		137: `^I`,
		138: `^J`,
		139: `^K`,
		140: `^L`,
		141: `^M`,
		142: `^N`,
		143: `^O`,
		144: `^P`,
		145: `^Q`,
		146: `^R`,
		147: `^S`,
		148: `^T`,
		149: `^U`,
		150: `^V`,
		151: `^W`,
		152: `^X`,
		153: `^Y`,
		154: `^Z`,
		155: `^[`,
		156: `^\\`,
		157: `^]`,
		158: `^^`,
		159: `^_`,
	}
	if c, ok := m[b[1]]; ok {
		return []byte(c), true
	}
	return b, false
}
