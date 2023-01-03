// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipsp

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
)

func TestParseCLenVal(t *testing.T) {
	type expRes struct {
		err  ErrorHdr
		offs int
		val  uint32
	}

	type testCase struct {
		clen string // content-length body without terminating CRLF
		expRes
	}
	var b []byte

	tests := [...]testCase{
		{clen: "1234", expRes: expRes{err: 0, val: 1234}},
		{clen: "1", expRes: expRes{err: 0, val: 1}},
		{clen: "0", expRes: expRes{err: 0, val: 0}},
		{clen: "0001234", expRes: expRes{err: 0, val: 1234}},
		{clen: "000056789", expRes: expRes{err: 0, val: 56789}},
		{clen: "0000567890",
			expRes: expRes{err: ErrHdrNumTooBig, val: 567890}},
		{clen: "16777217",
			expRes: expRes{err: ErrHdrNumTooBig, val: 16777217}},
		{clen: "1234 56789",
			expRes: expRes{err: ErrHdrBadChar, val: 1234}},
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
			iws := strings.IndexAny(c.clen, " \t\r\n")
			if iws > 0 {
				iws, _, _ = skipLWS([]byte(c.clen), iws, 0)
				c.offs = len(fWS) + iws
			} else {
				c.offs = len(fWS) + len(c.clen) + len(eWS) + 2
			}
		} // else offset is set, don't touch

		b = []byte(fWS + c.clen + eWS + "\r\n\r\n")
		testParseCLenExp(t, b, 0, c.err, []byte(c.clen), c.offs, c.val)
	}
}

func testParseCLenExp(t *testing.T, buf []byte, offs int, eErr ErrorHdr,
	eCLen []byte, eOffs int, eVal uint32) {

	var pcl PUIntBody

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
			o, err = ParseCLenVal(buf[:end], o, &pcl)
			if err != ErrHdrMoreBytes {
				t.Errorf("ParseCLenVal partial %d (%q/%q, %d, .)"+
					"=[%d, %d(%q)]"+" error %s (%q) expected, state %d soffs %d",
					i, buf[:end], buf, offs, o, err, err,
					ErrHdrMoreBytes, ErrHdrMoreBytes, pcl.state, pcl.soffs)
				if pcl.Parsed() {
					t.Errorf("ParseClenVal(%q, %d, ..)=[%d, %d(%q)] "+
						" unexpected final state %d while ErrHdrMoreBytes",
						buf, offs, o, err, err, pcl.state)
				}
			}
		} else {
			break
		}
	}
	o, err = ParseCLenVal(buf, o, &pcl)
	if err != eErr {
		t.Errorf("ParseCLenVal(%q, %d, ..)=[%d, %d(%q)]  error %s (%q) expected, state %d soffs %d",
			buf, offs, o, err, err, eErr, eErr, pcl.state, pcl.soffs)
	}
	if err != 0 {
		// no point in checking components if error
		return
	}
	if o != eOffs && eOffs != -1 {
		t.Errorf("ParseCLenVal(%q, %d, ..)=[%d, %d(%q)]  offset %d expected, state %d soffs %d",
			buf, offs, o, err, err, eOffs, pcl.state, pcl.soffs)
	}
	// take whitespace into account
	if !bytes.Equal(eCLen, pcl.SVal.Get(buf)) {
		t.Errorf("ParseClenVal(%q, %d, ..)=[%d, %d(%q)] clen %q != %q (exp)",
			buf, offs, o, err, err, pcl.SVal.Get(buf), eCLen)
	}
	if pcl.UIVal != eVal {
		t.Errorf("ParseClenVal(%q, %d, ..)=[%d, %d(%q)] clen val %d != %d"+
			" (exp)",
			buf, offs, o, err, err, pcl.UIVal, eVal)
	}
	if !pcl.Parsed() {
		t.Errorf("ParseClenVal(%q, %d, ..)=[%d, %d(%q)] "+
			" invalid/unexpected final state %d",
			buf, offs, o, err, err, pcl.state)
	}

}
