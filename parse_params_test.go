// Copyright 2021 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipsp

import (
	"testing"

	"bytes"
)

func TestSkipQuoted(t *testing.T) {
	type testCase struct {
		t     []byte   // test string
		offs  int      // offset in t
		eOffs int      // expected offset
		eErr  ErrorHdr // expected error
	}

	tests := [...]testCase{
		{t: []byte("q1 bar\""), offs: 0, eOffs: 7, eErr: ErrHdrOk},
		{t: []byte("q2 \\\" \\\" bar\""), offs: 0, eOffs: 13, eErr: ErrHdrOk},
		{t: []byte("q3 bar"), offs: 0, eOffs: 6, eErr: ErrHdrMoreBytes},
		{t: []byte("q4 bar\\"), offs: 0, eOffs: 6, eErr: ErrHdrMoreBytes},
		{t: []byte("q5 bar\n"), offs: 0, eOffs: 6, eErr: ErrHdrBadChar},
		{t: []byte("q6\rbar"), offs: 0, eOffs: 2, eErr: ErrHdrBadChar},
		{t: []byte("q6\\\nbar"), offs: 0, eOffs: 3, eErr: ErrHdrBadChar},
		{t: []byte("q5 bar\\\r"), offs: 0, eOffs: 7, eErr: ErrHdrBadChar},
	}

	for _, tc := range tests {
		var err ErrorHdr
		var nxtChr string
		o := tc.offs
		o, err = SkipQuoted(tc.t, o)

		if o == len(tc.t) {
			nxtChr = "EOF" // place holder for end of input
		} else if o > len(tc.t) {
			nxtChr = "ERR_OVERFLOW" // place holder for out of buffer
		} else {
			nxtChr = string(tc.t[o])
		}
		if err != tc.eErr {
			t.Errorf("TestSkipQuoted: error code mismatch: %d (%q),"+
				" expected %d (%q) for %q @%d ('%s')",
				err, err, tc.eErr, tc.eErr, tc.t, o, nxtChr)
		} else if o != tc.eOffs {
			t.Errorf("TestParseTokLst: offset mismatch: %d,"+
				" expected %d for %q",
				o, tc.eOffs, tc.t)
		}
	}
}

func TestParseTokenParam(t *testing.T) {
	type testCase struct {
		t     []byte    // test string
		offs  int       // offset in t
		flags POptFlags // parsing flags
		eAll  string    // expected trimmed param
		eName string    // expected trimmed param name
		eVal  string    // expected trimmed param value
		eOffs int       // expected offset
		eErr  ErrorHdr  // expected error
	}

	tests := [...]testCase{
		{t: []byte("p1\r\nX"), offs: 0, flags: 0,
			eAll: "p1", eName: "p1", eVal: "",
			eOffs: 4, eErr: ErrHdrEOH},
		{t: []byte("p2=v2\r\nX"), offs: 0, flags: 0,
			eAll: "p2=v2", eName: "p2", eVal: "v2",
			eOffs: 7, eErr: ErrHdrEOH},
		{t: []byte(" p3	 \r\nX"), offs: 0, flags: 0,
			eAll: "p3", eName: "p3", eVal: "",
			eOffs: 7, eErr: ErrHdrEOH},
		{t: []byte("	 p5 = v5 \r\nX"), offs: 0, flags: 0,
			eAll: "p5 = v5", eName: "p5", eVal: "v5",
			eOffs: 12, eErr: ErrHdrEOH},
		{t: []byte("p6=v6;foo=bar\r\nX"), offs: 0, flags: 0,
			eAll: "p6=v6", eName: "p6", eVal: "v6",
			eOffs: 6, eErr: ErrHdrMoreValues},
		{t: []byte("p7=v7;foo=bar\r\nX"), offs: 6, flags: 0,
			eAll: "foo=bar", eName: "foo", eVal: "bar",
			eOffs: 15, eErr: ErrHdrEOH},
		{t: []byte(" p8 = v8 ; foo = bar\r\nX"), offs: 0, flags: 0,
			eAll: "p8 = v8", eName: "p8", eVal: "v8",
			eOffs: 11, eErr: ErrHdrMoreValues},
		{t: []byte("p9=v9,foo\r\nX"), offs: 0, flags: POptTokCommaSepF,
			eAll: "p9=v9", eName: "p9", eVal: "v9",
			eOffs: 5, eErr: ErrHdrOk},
		{t: []byte("p10=v10 foo\r\nX"), offs: 0, flags: POptTokSpSepF,
			eAll: "p10=v10", eName: "p10", eVal: "v10",
			eOffs: 7, eErr: ErrHdrOk},
		{t: []byte("p11=v11   foo\r\nX"), offs: 0, flags: POptTokSpSepF,
			eAll: "p11=v11", eName: "p11", eVal: "v11",
			eOffs: 9, eErr: ErrHdrOk},
		{t: []byte("p12=v12 , foo\r\nX"), offs: 0,
			flags: POptTokCommaSepF | POptTokSpSepF,
			eAll:  "p12=v12", eName: "p12", eVal: "v12",
			eOffs: 8, eErr: ErrHdrOk},
		{t: []byte("p13;foo=bar\r\nX"), offs: 0, flags: 0,
			eAll: "p13", eName: "p13", eVal: "",
			eOffs: 4, eErr: ErrHdrMoreValues},
		{t: []byte("p14,foo=bar\r\nX"), offs: 0, flags: POptTokCommaSepF,
			eAll: "p14", eName: "p14", eVal: "",
			eOffs: 3, eErr: ErrHdrOk},
		{t: []byte("p15 foo=bar\r\nX"), offs: 0, flags: POptTokSpSepF,
			eAll: "p15", eName: "p15", eVal: "",
			eOffs: 3, eErr: ErrHdrOk},
		{t: []byte("p15 ; foo=bar\r\nX"), offs: 0, flags: POptTokSpSepF,
			eAll: "p15", eName: "p15", eVal: "",
			eOffs: 6, eErr: ErrHdrMoreValues},
		{t: []byte("p16\r\n"), offs: 0, flags: POptInputEndF,
			eAll: "p16", eName: "p16", eVal: "",
			eOffs: 5, eErr: ErrHdrEOH},
		{t: []byte("p17"), offs: 0, flags: POptInputEndF,
			eAll: "p17", eName: "p17", eVal: "",
			eOffs: 3, eErr: ErrHdrEOH},
		{t: []byte("p18=v18\r\n"), offs: 0, flags: POptInputEndF,
			eAll: "p18=v18", eName: "p18", eVal: "v18",
			eOffs: 9, eErr: ErrHdrEOH},
		{t: []byte("p19=v19"), offs: 0, flags: POptInputEndF,
			eAll: "p19=v19", eName: "p19", eVal: "v19",
			eOffs: 7, eErr: ErrHdrEOH},
		{t: []byte("test.foo.bar\r\nX"), offs: 0, flags: 0,
			eAll: "test.foo.bar", eName: "test.foo.bar", eVal: "",
			eOffs: 14, eErr: ErrHdrEOH},
		{t: []byte("test-1-2.foo.bar\r\nX"), offs: 0, flags: 0,
			eAll: "test-1-2.foo.bar", eName: "test-1-2.foo.bar", eVal: "",
			eOffs: 18, eErr: ErrHdrEOH},
	}

	var param PTokParam
	for _, tc := range tests {
		var err ErrorHdr
		var nxtChr string
		param.Reset()
		o := tc.offs

		o, err = ParseTokenParam(tc.t, o, &param, tc.flags)

		if o == len(tc.t) {
			nxtChr = "EOF" // place holder for end of input
		} else if o > len(tc.t) {
			nxtChr = "ERR_OVERFLOW" // place holder for out of buffer
		} else {
			nxtChr = string(tc.t[o])
		}

		if err != tc.eErr {
			t.Errorf("TestParseTokenParam: error code mismatch: %d (%q),"+
				" expected %d (%q) for %q @%d ('%s')",
				err, err, tc.eErr, tc.eErr, tc.t, o, nxtChr)
		} else {
			if o != tc.eOffs {
				t.Errorf("TestParseTokenParam: offset mismatch: %d,"+
					" expected %d for %q",
					o, tc.eOffs, tc.t)
			}
			if !bytes.Equal(param.All.Get(tc.t), []byte(tc.eAll)) {
				t.Errorf("TestParseTokenParam: All mismatch: %q,"+
					" expected %q for %q",
					param.All.Get(tc.t), tc.eAll, tc.t)
			}
			if !bytes.Equal(param.Name.Get(tc.t), []byte(tc.eName)) {
				t.Errorf("TestParseTokenParam: Name mismatch: %q,"+
					" expected %q for %q",
					param.Name.Get(tc.t), tc.eName, tc.t)
			}
			if !bytes.Equal(param.Val.Get(tc.t), []byte(tc.eVal)) {
				t.Errorf("TestParseTokenParam: Val mismatch: %q,"+
					" expected %q for %q",
					param.Val.Get(tc.t), tc.eVal, tc.t)
			}
		}
	}
}
