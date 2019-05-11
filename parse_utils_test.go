package sipsp

import (
	"testing"
)

func TestSkipCRLF(t *testing.T) {

	type testCase struct {
		t     []byte   // test "string"
		offs  int      // offset in t
		eOffs int      // expected offset
		eLen  int      // expected len
		eErr  ErrorHdr // expected error
	}
	tests := [...]testCase{
		{[]byte("\r\nX"), 0, 2, 2, ErrHdrOk},
		{[]byte("01\r\nX"), 2, 4, 2, ErrHdrOk},
		{[]byte("\r\n "), 0, 2, 2, ErrHdrOk},
		{[]byte("\r\n	"), 0, 2, 2, ErrHdrOk},
		{[]byte("\r\n   "), 0, 2, 2, ErrHdrOk},
		{[]byte("\r\n\r\n"), 0, 2, 2, ErrHdrOk},
		{[]byte("\r\n\n"), 0, 2, 2, ErrHdrOk},
		{[]byte("\r\n\r"), 0, 2, 2, ErrHdrOk},
		{[]byte("\rX"), 0, 1, 1, ErrHdrOk},
		{[]byte("\r\r"), 0, 1, 1, ErrHdrOk},
		{[]byte("\nX"), 0, 1, 1, ErrHdrOk},
		{[]byte("\n\n"), 0, 1, 1, ErrHdrOk},
		{[]byte("\n\r"), 0, 1, 1, ErrHdrOk},
		{[]byte("\r"), 0, 0, 0, ErrHdrMoreBytes},
		{[]byte("01\r"), 2, 2, 0, ErrHdrMoreBytes},
		{[]byte("x"), 0, 0, 0, ErrHdrNoCR},
		{[]byte("01X"), 2, 2, 0, ErrHdrNoCR},
		{[]byte("01"), 0, 0, 0, ErrHdrNoCR},
	}
	for _, tc := range tests {
		o, l, err := skipCRLF(tc.t, tc.offs)
		if err != tc.eErr {
			t.Errorf("skipCRLF(%q, %d)=[%d, %d, %d(%q)] expected error %d (%q)",
				tc.t, tc.offs, o, l, err, err, tc.eErr, tc.eErr)
		}
		if o != tc.eOffs {
			t.Errorf("skipCRLF(%q, %d)=[o:%d, l:%d, %d(%q)] expected offs %d",
				tc.t, tc.offs, o, l, err, err, tc.eOffs)
		}
		if l != tc.eLen {
			t.Errorf("skipCRLF(%q, %d)=[o:%d, l:%d, %d(%q)] expected len %d",
				tc.t, tc.offs, o, l, err, err, tc.eLen)
		}
	}
}

func TestSkipLWS(t *testing.T) {
	type testCase struct {
		t     []byte   // test "string"
		offs  int      // offset in t
		eOffs int      // expected offset
		eLen  int      // expected CR len
		eErr  ErrorHdr // expected error
	}
	tests := [...]testCase{
		{[]byte("\r\nX"), 0, 0, 2, ErrHdrEOH},
		{[]byte("\r\n\r\n"), 0, 0, 2, ErrHdrEOH},
		{[]byte("\r\n\r\n "), 0, 0, 2, ErrHdrEOH},
		{[]byte(" 	\r\nX"), 0, 2, 2, ErrHdrEOH},
		{[]byte(" 	\r\n \r\nX"), 0, 5, 2, ErrHdrEOH},
		{[]byte("\r\n 	\r\n \r\nX"), 0, 7, 2, ErrHdrEOH},
		{[]byte("\r\n 	\r\n \r\n\r\n"), 0, 7, 2, ErrHdrEOH},
		{[]byte("\r\n "), 0, 3, 0, ErrHdrMoreBytes},
		{[]byte(" \r\n \r\n "), 0, 7, 0, ErrHdrMoreBytes},
		{[]byte(" \r\n \r\n "), 3, 7, 0, ErrHdrMoreBytes},
		{[]byte(" 	 "), 0, 3, 0, ErrHdrMoreBytes},
		{[]byte(" 	 x"), 0, 3, 0, 0},
		{[]byte("\r\n x"), 0, 3, 0, 0},
	}
	for _, tc := range tests {
		o, l, err := skipLWS(tc.t, tc.offs)
		if err != tc.eErr {
			t.Errorf("skipLWS(%q, %d)=[%d, %d, %d(%q)] expected error %d (%q)",
				tc.t, tc.offs, o, l, err, err, tc.eErr, tc.eErr)
		}
		if o != tc.eOffs {
			t.Errorf("skipLWS(%q, %d)=[o:%d, l:%d, %d(%q)] expected offs %d",
				tc.t, tc.offs, o, l, err, err, tc.eOffs)
		}
		if l != tc.eLen {
			t.Errorf("skipLWS(%q, %d)=[o:%d, l:%d, %d(%q)] expected len %d",
				tc.t, tc.offs, o, l, err, err, tc.eLen)
		}
	}
}
