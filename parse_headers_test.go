package sipsp

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
	"unsafe"

	"andrei/sipsp/bytescase"
)

// randomize case in a string
func randCase(s string) string {
	r := make([]byte, len(s))
	for i, b := range []byte(s) {
		switch rand.Intn(3) {
		case 0:
			r[i] = bytescase.ByteToLower(b)
		case 1:
			r[i] = bytescase.ByteToUpper(b)
		default:
			r[i] = b
		}
	}
	return string(r)
}

func TestHdrNameLookup(t *testing.T) {
	// statistics
	var max, crowded, total int
	for _, l := range hdrNameLookup {
		if len(l) > max {
			max = len(l)
		}
		if len(l) > 1 {
			crowded++
		}
		total += len(l)
	}
	if total != len(hdrName2Type) {
		t.Errorf("init: hdrNameLookup[%d][..]:"+
			" lookup hash has too few elements %d/%d (max %d, crowded %d)\n",
			len(hdrNameLookup), total, len(hdrName2Type), max, crowded)
	}
	if max > 2 { // Contact & Call-ID hash to the same value
		t.Errorf("init: hdrNameLookup[%d][..]: max %d, crowded %d, total %d"+
			" - try increasing hnBitsLen(%d) and/or hnBitsFChar(%d)\n",
			len(hdrNameLookup), max, crowded, total, hnBitsLen, hnBitsFChar)
	}
	if max > 0 {
		t.Logf("init: hdrNameLookup[%d][..]: max %d, crowded %d, total %d\n",
			len(hdrNameLookup), max, crowded, total)
	}
}

func TestHdrFlags(t *testing.T) {
	var f HdrFlags
	if unsafe.Sizeof(f)*8 <= uintptr(HdrOther) {
		t.Errorf("HdrFlags: flags type too small: %d bits but %d needed\n",
			unsafe.Sizeof(f)*8, HdrOther)
	}
	for h := HdrNone; h <= HdrOther; h++ {
		f.Set(h)
		if !f.Test(h) {
			t.Errorf("HdrFlags.Test(%v): wrong return\n", f)
		}
	}
	for h := HdrNone; h <= HdrOther; h++ {
		f.Clear(h)
		if f.Test(h) {
			t.Errorf("HdrFlags.Test(%v): wrong return\n", f)
		}
	}

}

func TestHdr2Str(t *testing.T) {
	if len(hdrTStr) != (int(HdrOther) + 1) {
		t.Errorf("hdrTStr[]: length mismatch %d/%d\n",
			len(hdrTStr), int(HdrOther)+1)
	}
	for i, v := range hdrTStr {
		if len(v) == 0 {
			t.Errorf("hdrTStr[%d]: empty name\n", i)
		}
	}
	for h := HdrNone; h <= HdrOther; h++ {
		if len(h.String()) == 0 || strings.EqualFold(h.String(), "invalid") {
			t.Errorf("header type %d has invalid string value %q\n",
				h, h.String())
		}
	}

}

type eRes struct {
	err  ErrorHdr
	offs int
	t    HdrT
	hn   []byte
	hv   []byte
}

type testCase struct {
	n string // header name (without ':')
	b string // header body (without CRLF)
	eRes
}

var testsHeaders = [...]testCase{
	{n: "From", b: "foo@test.org", eRes: eRes{err: 0, t: HdrFrom}},
	{n: "f", b: "foo@test.org", eRes: eRes{err: 0, t: HdrFrom}},
	{n: "t", b: "Foo Bar <x@bar.com>;tag=1",
		eRes: eRes{err: 0, t: HdrTo}},
	{n: "To", b: "<x@bar.com>;tag=1234;x=y",
		eRes: eRes{err: 0, t: HdrTo}},
	{n: "Call-ID", b: "annZassdd32", eRes: eRes{err: 0, t: HdrCallID}},
	{n: "I", b: "aaBBDAasdssa@x.y", eRes: eRes{err: 0, t: HdrCallID}},
	{n: "Cseq", b: "12345 INVITE", eRes: eRes{err: 0, t: HdrCSeq}},
	{n: "Content-Length", b: "12345", eRes: eRes{err: 0, t: HdrCLen}},
	{n: "L", b: "0", eRes: eRes{err: 0, t: HdrCLen}},
	{n: "Foo", b: "generic header", eRes: eRes{err: 0, t: HdrOther}},
}

func TestParseHdrLine(t *testing.T) {

	var b []byte
	ws := [...][3]string{
		{"", "", ""},
		{"", " ", ""},
		{" ", " ", " "},
	}
	tests := testsHeaders

	for i := 0; i < (len(ws) + 2); i++ {
		for _, c := range tests {
			var ws1, lws, lwsE, n string
			if i < len(ws) {
				ws1 = ws[i][0]
				lws = ws[i][1]
				lwsE = ws[i][2]
			} else {
				ws1 = randWS()
				lws = randLWS()
				lwsE = randLWS()
			}
			if i%2 == 1 {
				n = randCase(c.n)
			} else {
				n = c.n
			}
			b = []byte(n + ws1 + ":" + lws + c.b + lwsE + "\r\n\r\n")
			c.offs = len(b) - 2
			c.hn = []byte(n)
			c.hv = []byte(c.b)
			var hdr Hdr
			var phvals PHdrVals
			testParseHdrLine(t, b, 0, &hdr, nil, &c.eRes)
			hdr.Reset()
			testParseHdrLine(t, b, 0, &hdr, &phvals, &c.eRes)
			testParseHdrLinePieces(t, b, 0, &c.eRes, 10)
		}
	}
}

func testParseHdrLine(t *testing.T, buf []byte, offs int, hdr *Hdr, phb PHBodies, e *eRes) {

	var err ErrorHdr
	o := offs
	o, err = ParseHdrLine(buf, o, hdr, phb)
	if err != e.err {
		t.Errorf("ParseHdrLine(%q, %d, ..)=[%d, %d(%q)]  error %s (%q) expected, state %d",
			buf, offs, o, err, err, e.err, e.err, hdr.state)
	}
	if o != e.offs {
		t.Errorf("ParseHdrLine(%q, %d, ..)=[%d, %d(%q)]  offset %d expected, state %d",
			buf, offs, o, err, err, e.offs, hdr.state)
	}
	if err != 0 {
		return
	}
	if hdr.Type != e.t {
		t.Errorf("ParseHdrLine(%q, %d, ..)=[%d, %d(%q)]  type %d %q != %d %q (exp), state %d",
			buf, offs, o, err, err, hdr.Type, hdr.Type, e.t, e.t, hdr.state)
	}

	if !bytes.Equal(e.hn, hdr.Name.Get(buf)) {
		t.Errorf("ParseHdrLine(%q, %d, ..)=[%d, %d(%q)]  hdr name %q !=  %q (exp), state %d",
			buf, offs, o, err, err, hdr.Name.Get(buf), e.hn, hdr.state)
	}
	if !bytes.Equal(e.hv, hdr.Val.Get(buf)) {
		t.Errorf("ParseHdrLine(%q, %d, ..)=[%d, %d(%q)]  hdr val %q !=  %q (exp), state %d",
			buf, offs, o, err, err, hdr.Val.Get(buf), e.hv, hdr.state)
	}
}

func testParseHdrLinePieces(t *testing.T, buf []byte, offs int, e *eRes, n int) {
	var err ErrorHdr
	var hdr Hdr
	var phvals PHdrVals
	o := offs
	pieces := rand.Intn(n)
	for i := 0; i < pieces; i++ {
		sz := rand.Intn(len(buf) + 1 - o)
		end := sz + o
		if end < e.offs {
			o, err = ParseHdrLine(buf[:end], o, &hdr, &phvals)
			if err != ErrHdrMoreBytes {
				t.Errorf("ParseHdrLine partial (%q, %d, ..)=[%d, %d(%q)] "+
					"  error %s (%q) expected, state %d",
					buf, offs, o, err, err, ErrHdrMoreBytes, ErrHdrMoreBytes,
					hdr.state)
			}
		} else {
			break
		}
	}
	testParseHdrLine(t, buf, o, &hdr, &phvals, e)
}

type mTest struct {
	m    string
	err  ErrorHdr
	n    int
	offs int
}

func TestParseHeaders(t *testing.T) {
	tests := [...]mTest{
		{m: `From: <a@foo.bar>;tag=1234
To:<x@y.com>
Call-ID: a84b4c76e66710
CSeq: 314159 INVITE
Via: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bKnashds8
Max-Forwards: 70
Date: Thu, 21 Feb 2002 13:02:03 GMT
Content-Length: 568
`, n: 8},
		{m: `From: <b@foo.bar>;tag=1234\r
To:<x@y.com>\r
Call-ID: a84b4c76e66710\r
CSeq: 314159 INVITE\r
Via: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bKnashds8\r
Max-Forwards: 70\r
Date: Thu, 21 Feb 2002 13:02:03 GMT\r
Content-Length: 568\r
`, n: 8},
		{m: `From: <b@foo.bar>;tag=1234\r
To:<x@y.com>\r
Call-ID: a84b4c76e66710\r
From: Second From <x@q.b>;tag=5678\r
CSeq: 314159 INVITE\r
CSeq: 914159 CANCEL\r
Via: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bKnashds8\r
Max-Forwards: 70\r
Date: Thu, 21 Feb 2002 13:02:03 GMT\r
Content-Length: 568\r
`, n: 10},
	}
	var hl HdrLst
	var hdrs [20]Hdr
	var phv PHdrVals

	offs := 0
	hl.Hdrs = hdrs[:]
	for _, c := range tests {
		buf := []byte(c.m + "\r\n")
		if c.offs == 0 {
			c.offs = len(buf)
		}
		testParseHeaders(t, buf, offs, &hl, &phv, &c)
		// debugging
		/*
			for i, h := range hl.Hdrs {
				if i >= hl.N {
					break
				}
				t.Logf("H%2d %q : %q [%q]\n",
					i, h.Name.Get(buf), h.Val.Get(buf), h.Type)
			}
		*/
		hl.Reset()
		testParseHeadersPieces(t, buf, offs, &hl, &phv, &c, 20)
		hl.Reset()
	}
}

func testParseHeaders(t *testing.T, buf []byte, offs int, hl *HdrLst, hb PHBodies, e *mTest) {
	o, err := ParseHeaders(buf, offs, hl, hb)
	if err != e.err {
		t.Errorf("ParseHeaders(%q, %d, ..)=[%d, %d(%q)]  error %s (%q) expected",
			buf, offs, o, err, err, e.err, e.err)
	}
	if o != e.offs {
		t.Errorf("ParseHeaders(%q, %d, ..)=[%d, %d(%q)]  offset %d expected",
			buf, offs, o, err, err, e.offs)
	}
	if hl.N != e.n {
		t.Errorf("ParseHeaders(%q, %d, ..)=[%d, %d(%q)] %d headers instead of %d ",
			buf, offs, o, err, err, hl.N, e.n)
	}
}

func testParseHeadersPieces(t *testing.T, buf []byte, offs int, hl *HdrLst, hb PHBodies, e *mTest, n int) {

	var err ErrorHdr
	o := offs
	pieces := rand.Intn(n)
	for i := 0; i < pieces; i++ {
		sz := rand.Intn(len(buf) + 1 - o)
		end := sz + o
		if end < e.offs {
			o, err = ParseHeaders(buf[:end], o, hl, hb)
			if err != ErrHdrMoreBytes {
				t.Errorf("ParseHeaders partial (%q, %d, ..)=[%d, %d(%q)] "+
					"  error %s (%q) expected",
					buf, offs, o, err, err, ErrHdrMoreBytes, ErrHdrMoreBytes)
			}
		} else {
			break
		}
	}
	testParseHeaders(t, buf, o, hl, hb, e)
}
