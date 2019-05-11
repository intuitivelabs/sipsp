package sipsp

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
)

func TestParseCallIDVal1(t *testing.T) {
	type expRes struct {
		err  ErrorHdr
		offs int
	}

	type testCase struct {
		callid string // callid body w/o term. CRLF
		expRes
	}
	var b []byte

	tests := [...]testCase{
		{callid: "AbxeeddsjhjfhjeH12", expRes: expRes{err: 0}},
		{callid: "=mHef&13jejfneu8u<\"@foo.bar", expRes: expRes{err: 0}},
		{callid: "a84b4c76e66710", expRes: expRes{err: 0, offs: -1}},
		{callid: "f81d4fae-7dec-11d0-a765-00a0c91e6bf6@biloxi.com"},
		{callid: "f81d4fae-7dec-11d0-a765-00a0c91e6bf6@192.0.2.4",
			expRes: expRes{err: 0, offs: -1}},
		{callid: "843817637684230@998sdasdh09", expRes: expRes{err: 0}},
		{callid: "a84b4 c76e66710", expRes: expRes{err: ErrHdrBadChar}},
		{callid: "a84b4	c76e66710", expRes: expRes{err: ErrHdrBadChar}},
		{callid: "a84b4\n c76e66710", expRes: expRes{err: ErrHdrBadChar}},
		{callid: "a84b4\r c76e66710", expRes: expRes{err: ErrHdrBadChar}},
		{callid: "a84b4\r\n c76e66710", expRes: expRes{err: ErrHdrBadChar}},
		{callid: "a84b4 \r\n c76e66710", expRes: expRes{err: ErrHdrBadChar}},
		{callid: "a84b4	\r\n	c76e66710", expRes: expRes{err: ErrHdrBadChar}},
		{callid: "X", expRes: expRes{err: 0, offs: 3 /* 1 + CRLF */}},
	}

	for _, c := range tests {
		fWS := ""
		eWS := ""
		// offs == 0 -> add random LWS and compute expected offset
		// offs < 0  -> don't add anything, but compute expected offset
		// offs > 0  -> don't add anything and don't re-compute the offset

		if c.offs == 0 {
			// offset not filled -> add random WS
			fWS = randLWS()
			eWS = randLWS()
		}
		if c.offs <= 0 {
			// offset not filled (0) or negative => compute it
			// if there is any whitespace in the callid value, that
			// should be the offset
			iws := strings.IndexAny(c.callid, " \t\r\n")
			if iws > 0 {
				iws, _, _ = skipLWS([]byte(c.callid), iws)
				c.offs = len(fWS) + iws
			} else {
				c.offs = len(fWS) + len(c.callid) + len(eWS) + 2
			}
		} // else offset is set, don't touch

		b = []byte(fWS + c.callid + eWS + "\r\n\r\n")
		testParseCallIDExp(t, b, 0, c.err, []byte(c.callid), c.offs)
	}
}

func testParseCallIDExp(t *testing.T, buf []byte, offs int, eErr ErrorHdr,
	eCallID []byte, eOffs int) {

	var pcid PCallIDBody

	var sz int
	var o int
	var err ErrorHdr
	o = offs
	pieces := rand.Intn(10)
	var i int
	for ; i < pieces; i++ {
		sz = rand.Intn(len(buf) + 1 - o)
		end := sz + o
		if end < eOffs {
			o, err = ParseCallIDVal(buf[:end], o, &pcid)
			if err != ErrHdrMoreBytes {
				t.Errorf("ParseCallIDVal partial %d (%q/%q, %d, .)"+
					"=[%d, %d(%q)]"+" error %s (%q) expected, state %d soffs %d",
					i, buf[:end], buf, offs, o, err, err,
					ErrHdrMoreBytes, ErrHdrMoreBytes, pcid.state, pcid.soffs)
			}
			if pcid.Parsed() {
				t.Errorf("ParseCallIDVal(%q, %d, ..)=[%d, %d(%q)]"+
					" unexpected final state %d while ErrHdrMoreBytes",
					buf, offs, o, err, err, pcid.state)
			}
		} else {
			break
		}
	}
	o, err = ParseCallIDVal(buf, o, &pcid)
	/*
		if pieces > 0 {
			fmt.Printf("final(%d) bytes %q -> offset %d, err %d [%s], state %d soffs %d\n", i, buf, o, err, err, pcid.state, pcid.soffs)
		}
	*/
	if err != eErr {
		t.Errorf("ParseCallIDVal(%q, %d, ..)=[%d, %d(%q)]  error %s (%q) expected, state %d soffs %d",
			buf, offs, o, err, err, eErr, eErr, pcid.state, pcid.soffs)
	}
	if o != eOffs && eOffs != -1 {
		t.Errorf("ParseCallIDVal(%q, %d, ..)=[%d, %d(%q)]  offset %d expected, state %d soffs %d",
			buf, offs, o, err, err, eOffs, pcid.state, pcid.soffs)
	}
	if err != 0 {
		// no point in checking components if error
		return
	}
	// take whitespace into account
	if !bytes.Equal(eCallID, pcid.CallID.Get(buf)) {
		t.Errorf("ParseCallIDVal(%q, %d, ..)=[%d, %d(%q)] callid %q != %q (exp)",
			buf, offs, o, err, err, pcid.CallID.Get(buf), eCallID)
	}
	if !pcid.Parsed() {
		t.Errorf("ParseCallIDVal(%q, %d, ..)=[%d, %d(%q)]"+
			" unexpected final state %d",
			buf, offs, o, err, err, pcid.state)
	}

}
