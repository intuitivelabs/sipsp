// // Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
// //
// // Use of this source code is governed by source-available license
// // that can be found in the LICENSE file in the root of the source
// // tree.

package sipsp

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
)

func TestParseCSeqVal(t *testing.T) {
	type expRes struct {
		err  ErrorHdr
		offs int
		val  uint32
		m    SIPMethod
	}

	type testCase struct {
		cseqN  string // cseq number
		method string // cseq method
		expRes
	}
	var b []byte
	var exp expCSeqRes

	tests := [...]testCase{
		{cseqN: "1234", method: "INVITE",
			expRes: expRes{err: 0, val: 1234, m: MInvite}},
		{cseqN: "001234", method: "ACK",
			expRes: expRes{err: 0, val: 1234, m: MAck}},
		{cseqN: "0", method: "REGISTER", expRes: expRes{val: 0, m: MRegister}},
		{cseqN: "1", method: "BYE", expRes: expRes{val: 1, m: MBye}},
		{cseqN: "2", method: "PRACK", expRes: expRes{val: 2, m: MPrack}},
		{cseqN: "3", method: "OPTIONS", expRes: expRes{val: 3, m: MOptions}},
		{cseqN: "4", method: "SUBSCRIBE", expRes: expRes{val: 4, m: MSubscribe}},
		{cseqN: "5", method: "INFO", expRes: expRes{val: 5, m: MInfo}},
		{cseqN: "6", method: "UPDATE", expRes: expRes{val: 6, m: MUpdate}},
		{cseqN: "7", method: "CANCEL", expRes: expRes{val: 7, m: MCancel}},
		{cseqN: "8", method: "NOTIFY", expRes: expRes{val: 8, m: MNotify}},
		{cseqN: "9", method: "REFER", expRes: expRes{val: 9, m: MRefer}},
		{cseqN: "10", method: "MESSAGE", expRes: expRes{val: 10, m: MMessage}},
		{cseqN: "11", method: "PUBLISH", expRes: expRes{val: 11, m: MPublish}},
		{cseqN: "5678", method: "FOO", expRes: expRes{val: 5678, m: MOther}},
	}

	for _, c := range tests {
		fWS := "" // front space
		eWS := "" // end space
		mWS := "" // "middle" space (between cseq and method)
		// offs == 0 -> add random LWS and compute expected offset
		// offs < 0  -> don't add anything, but compute expected offset
		// offs > 0  -> don't add anything and don't re-compute the offset

		if c.offs == 0 {
			// offset not filled -> add random WS
			fWS = randLWS()
			eWS = randLWS()
			mWS = randLWS()
		}
		if len(mWS) == 0 {
			mWS = " " // need at least one space
		}
		if c.offs <= 0 {
			// offset not filled (0) or negative => compute it
			// if there is any whitespace in the method value, that
			// should be the offset
			iws := strings.IndexAny(c.method, " \t\r\n")
			if iws > 0 {
				iws, _, _ = skipLWS([]byte(c.method), iws)
				c.offs = len(fWS) + len(c.cseqN) + len(mWS) + iws
			} else {
				c.offs = len(fWS) + len(c.cseqN) + len(mWS) + len(c.method) +
					len(eWS) + 2
			}
		} // else offset is set, don't touch

		b = []byte(fWS + c.cseqN + mWS + c.method + eWS + "\r\n\r\n")
		exp.cseq = []byte(c.cseqN)
		exp.method = []byte(c.method)
		exp.v = bytes.TrimSpace(b)
		exp.cseqVal = c.val
		exp.methodVal = c.m
		exp.offs = c.offs
		exp.err = c.err
		testParseCSeqExp(t, b, 0, exp)
	}
}

type expCSeqRes struct {
	err       ErrorHdr
	offs      int
	cseqVal   uint32
	methodVal SIPMethod
	cseq      []byte
	method    []byte
	v         []byte // whole body value, trimmed
}

func testParseCSeqExp(t *testing.T, buf []byte, offs int, exp expCSeqRes) {

	var pcs PCSeqBody

	var sz int
	var o int
	var err ErrorHdr
	o = offs
	pieces := rand.Intn(10)
	var i int
	for ; i < pieces; i++ {
		sz = rand.Intn(len(buf) + 1 - o)
		end := sz + o
		if end < exp.offs {
			o, err = ParseCSeqVal(buf[:end], o, &pcs)
			if err != ErrHdrMoreBytes {
				t.Errorf("ParseCSeqVal partial %d (%q/%q, %d, .)"+
					"=[%d, %d(%q)]"+" error %s (%q) expected, state %d soffs %d",
					i, buf[:end], buf, offs, o, err, err,
					ErrHdrMoreBytes, ErrHdrMoreBytes, pcs.state, pcs.soffs)
			}
			if pcs.Parsed() {
				t.Errorf("ParseCSeqVal(%q, %d, ..)=[%d, %d(%q)]"+
					" unexpected final state %d while ErrHdrMoreBytes",
					buf, offs, o, err, err, pcs.state)
			}
		} else {
			break
		}
	}
	o, err = ParseCSeqVal(buf, o, &pcs)
	if err != exp.err {
		t.Errorf("ParseCSeqVal(%q, %d, ..)=[%d, %d(%q)]  error %s (%q) expected, state %d soffs %d",
			buf, offs, o, err, err, exp.err, exp.err, pcs.state, pcs.soffs)
	}
	if o != exp.offs && exp.offs != -1 {
		t.Errorf("ParseCSeqVal(%q, %d, ..)=[%d, %d(%q)]  offset %d expected, state %d soffs %d",
			buf, offs, o, err, err, exp.offs, pcs.state, pcs.soffs)
	}
	if err != 0 {
		// no point in checking components if error
		return
	}
	// take whitespace into account
	if !bytes.Equal(exp.cseq, pcs.CSeq.Get(buf)) {
		t.Errorf("ParseCSeqVal(%q, %d, ..)=[%d, %d(%q)] cseq %q != %q (exp)",
			buf, offs, o, err, err, pcs.CSeq.Get(buf), exp.cseq)
	}
	if pcs.CSeqNo != exp.cseqVal {
		t.Errorf("ParseCSeqVal(%q, %d, ..)=[%d, %d(%q)] cseq val %d != %d"+
			" (exp)",
			buf, offs, o, err, err, pcs.CSeqNo, exp.cseqVal)
	}
	// take whitespace into account
	if !bytes.Equal(exp.method, pcs.Method.Get(buf)) {
		t.Errorf("ParseCSeqVal(%q, %d, ..)=[%d, %d(%q)] method %q != %q (exp)",
			buf, offs, o, err, err, pcs.Method.Get(buf), exp.method)
	}
	// check method no
	if pcs.MethodNo != exp.methodVal && exp.methodVal != 0 {
		t.Errorf("ParseCSeqVal(%q, %d, ..)=[%d, %d(%q)] method"+
			" val %d [%s] != %d [%s]"+" (exp)",
			buf, offs, o, err, err, pcs.MethodNo, pcs.MethodNo.Name(),
			exp.methodVal, exp.methodVal.Name())
	}
	// take whitespace into account
	if !bytes.Equal(exp.v, pcs.V.Get(buf)) {
		t.Errorf("ParseCSeqVal(%q, %d, ..)=[%d, %d(%q)]"+
			" trimmed body %q != %q (exp)",
			buf, offs, o, err, err, pcs.V.Get(buf), exp.v)
	}
	if !pcs.Parsed() {
		t.Errorf("ParseCSeqVal(%q, %d, ..)=[%d, %d(%q)]"+
			" unexpected final state %d",
			buf, offs, o, err, err, pcs.state)
	}

}
