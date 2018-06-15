package abdecrypt

import (
	"bytes"
	"unicode/utf16"
	"unicode/utf8"
)

// convertJavaStringToUTF8 converts byte-mapped Java string
// into UTF-8 encoded sequence.
// This is only used in master key checksum calculation and
// roots in Android bug as it treats input sequence as ASCII text.
func convertJavaStringToUTF8(p []byte) []byte {
	ret := &bytes.Buffer{}
	buf := make([]byte, 4)
	for _, b := range p {
		t := uint16(b)
		// perform sign extension
		if int8(b) < 0 {
			t |= 0xFF00
		}
		rr := utf16.Decode([]uint16{t})
		n := utf8.EncodeRune(buf, rr[0])
		ret.Write(buf[:n])
	}
	return ret.Bytes()
}
