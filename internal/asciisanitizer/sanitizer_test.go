package asciisanitizer

import (
	"bytes"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
	"golang.org/x/text/transform"
)

func TestSanitizerTransform(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "No control characters",
			input: `The quick brown fox\tjumped over the lazy dog\n`,
			want:  `The quick brown fox\tjumped over the lazy dog\n`,
		},
		{
			name:  "C0 control character",
			input: `1\u0001`,
			want:  "1^A",
		},
		{
			name: "C0 control characters",
			input: `1\u0001 2\u0002 3\u0003 4\u0004 5\u0005 6\u0006 7\u0007 8\u0008 9\t ` +
				`A\r\n B\u000b C\u000c D\r\n E\u000e F\u000f ` +
				`10\u0010 11\u0011 12\u0012 13\u0013 14\u0014 15\u0015 16\u0016 17\u0017 18\u0018 19\u0019 ` +
				`1A\u001a 1B\u001b 1C\u001c 1D\u001d 1E\u001e 1F\u001f ` +
				`\\u00\u001b ` +
				`\u001B \\u001B \\\u001B \\\\u001B `,
			want: `1^A 2^B 3^C 4^D 5^E 6^F 7^G 8^H 9\t ` +
				`A\r\n B^K C^L D\r\n E^N F^O ` +
				`10^P 11^Q 12^R 13^S 14^T 15^U 16^V 17^W 18^X 19^Y ` +
				`1A^Z 1B^[ 1C^\\ 1D^] 1E^^ 1F^_ ` +
				`\\u00^[ ` +
				`^[ \\^[ \\^[ \\\\^[ `,
		},
		{
			name:  "C1 control character",
			input: "80\xC2\x80",
			want:  "80^@",
		},
		{
			name: "C1 control characters",
			input: "80\xC2\x80 81\xC2\x81 82\xC2\x82 83\xC2\x83 84\xC2\x84 85\xC2\x85 86\xC2\x86 87\xC2\x87 88\xC2\x88 89\xC2\x89 " +
				"8A\xC2\x8A 8B\xC2\x8B 8C\xC2\x8C 8D\xC2\x8D 8E\xC2\x8E 8F\xC2\x8F " +
				"90\xC2\x90 91\xC2\x91 92\xC2\x92 93\xC2\x93 94\xC2\x94 95\xC2\x95 96\xC2\x96 97\xC2\x97 98\xC2\x98 99\xC2\x99 " +
				"9A\xC2\x9A 9B\xC2\x9B 9C\xC2\x9C 9D\xC2\x9D 9E\xC2\x9E 9F\xC2\x9F " +
				"\xC2\xA1 ",
			want: "80^@ 81^A 82^B 83^C 84^D 85^E 86^F 87^G 88^H 89^I " +
				"8A^J 8B^K 8C^L 8D^M 8E^N 8F^O " +
				"90^P 91^Q 92^R 93^S 94^T 95^U 96^V 97^W 98^X 99^Y " +
				"9A^Z 9B^[ 9C^\\\\ 9D^] 9E^^ 9F^_ " +
				"¡ ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitizer := &Sanitizer{}
			reader := bytes.NewReader([]byte(tt.input))
			transformReader := transform.NewReader(reader, sanitizer)
			err := iotest.TestReader(transformReader, []byte(tt.want))
			require.NoError(t, err)
		})
	}
}
