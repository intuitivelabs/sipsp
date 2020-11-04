// // Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
// //
// // Use of this source code is governed by source-available license
// // that can be found in the LICENSE file in the root of the source
// // tree.

package sipsp

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestMthNameLookup(t *testing.T) {
	// statistics
	var max, crowded, total int
	for _, l := range mthNameLookup {
		if len(l) > max {
			max = len(l)
		}
		if len(l) > 1 {
			crowded++
		}
		total += len(l)
	}
	if total != int(MOther)-1 {
		t.Errorf("init: mthNameLookup[%d][..]:"+
			" lookup hash has too few elements %d/%d  (max %d, crowded %d)\n",
			len(mthNameLookup), total, MOther-1, max, crowded)
	}
	if max > 2 {
		t.Errorf("init: mthNameLookup[%d][..]: max %d, crowded %d, total %d\n",
			len(mthNameLookup), max, crowded, total)
	}
	if max > 0 {
		t.Logf("init: mthNameLookup[%d][..]: max %d, crowded %d, total %d\n",
			len(mthNameLookup), max, crowded, total)
	}
}

type pflERes struct {
	err  ErrorHdr
	offs int
	t    SIPMethod
	s    uint16 // reply code
	m    []byte // method
	u    []byte // uri
	v    []byte // version
	sc   []byte // reply status code as "string"
	r    []byte // reply reason
}

func TestParseFLine(t *testing.T) {
	type testCase struct {
		t1, t2, t3 string // 3 tokens: method, uri, ver or ver status reas
		pflERes
	}

	tests := [...]testCase{
		{"INVITE", "sip:foo@bar.com", "SIP/2.0",
			pflERes{err: 0, t: MInvite}},
		{"REGISTER", "sip:f@b.com:5060", "SIP/2.0",
			pflERes{err: 0, t: MRegister}},
		{"ACK", "sip:bar.com;p=v", "SIP/2.0",
			pflERes{err: 0, t: MAck}},
		{"BYE", "sip:foo@bar.com?h1", "SIP/2.0",
			pflERes{err: 0, t: MBye}},
		{"CANCEL", "sip:foo@bar.com?h1;h2=h3", "SIP/2.0",
			pflERes{err: 0, t: MCancel}},
		{"PRACK", "sip:123456@x.com", "SIP/2.0",
			pflERes{err: 0, t: MPrack}},
		{"SIP/2.0", "200", "Ok",
			pflERes{err: 0, s: 200}},
		{"SIP/2.0", "401", "Unauthorized",
			pflERes{err: 0, s: 401}},
		{"SIP/2.0", "480", "Temporarily not available",
			pflERes{err: 0, s: 480}},
		{"SIP/2.0", "500", "Internal Sever Error  	 ",
			pflERes{err: 0, s: 500}},
		{"SIP/2.0", "100", "",
			pflERes{err: 0, s: 100}},
		{"SIP/2.0", "110", "	",
			pflERes{err: 0, s: 110}},
		{"SIP/2.0", "120", " ",
			pflERes{err: 0, s: 120}},
	}

	for _, c := range tests {
		b := []byte(c.t1 + " " + c.t2 + " " + c.t3 + "\r\n")
		c.offs = len(b)
		if c.s == 0 {
			// request
			c.m = []byte(c.t1)
			c.u = []byte(c.t2)
			c.v = []byte(c.t3)
		} else {
			c.v = []byte(c.t1)
			c.sc = []byte(c.t2)
			c.r = []byte(c.t3)
		}
		testParseFLinePieces(t, b, 0, &c.pflERes, 10)
	}
}

func testParseFLineExp(t *testing.T, buf []byte, offs int, fl *PFLine, e *pflERes) {
	var err ErrorHdr
	o := offs
	o, err = ParseFLine(buf, o, fl)
	if err != e.err {
		t.Errorf("ParseFLine(%q, %d, ..)=[%d, %d(%q)]  error %s (%q) expected, state %d",
			buf, offs, o, err, err, e.err, e.err, fl.state)
	}
	if o != e.offs {
		t.Errorf("ParseFLine(%q, %d, ..)=[%d, %d(%q)]  offset %d expected, state %d",
			buf, offs, o, err, err, e.offs, fl.state)
	}
	if err != 0 {
		return
	}
	if fl.Status != e.s {
		t.Errorf("ParseFLine(%q, %d, ..)=[%d, %d(%q)]"+
			"  status %d != %d , state %d",
			buf, offs, o, err, err, fl.Status, e.s, fl.state)
	}
	if fl.MethodNo != e.t {
		t.Errorf("ParseFLine(%q, %d, ..)=[%d, %d(%q)]"+
			"  method %d %q != %d %q, state %d",
			buf, offs, o, err, err,
			fl.MethodNo, fl.MethodNo, e.t, e.t, fl.state)
	}
	// request tests
	if !bytes.Equal(fl.Method.Get(buf), e.m) {
		t.Errorf("ParseFLine(%q, %d, ..)=[%d, %d(%q)]"+
			"  method str %q != %q, state %d",
			buf, offs, o, err, err, fl.Method.Get(buf), e.m, fl.state)
	}
	if !bytes.Equal(fl.URI.Get(buf), e.u) {
		t.Errorf("ParseFLine(%q, %d, ..)=[%d, %d(%q)]"+
			"  URI str %q != %q, state %d",
			buf, offs, o, err, err, fl.URI.Get(buf), e.u, fl.state)
	}
	if !bytes.Equal(fl.Version.Get(buf), e.v) {
		t.Errorf("ParseFLine(%q, %d, ..)=[%d, %d(%q)]"+
			"  version str %q != %q, state %d",
			buf, offs, o, err, err, fl.Version.Get(buf), e.v, fl.state)
	}
	// reply specific
	if !bytes.Equal(fl.StatusCode.Get(buf), e.sc) {
		t.Errorf("ParseFLine(%q, %d, ..)=[%d, %d(%q)]"+
			"  status str %q != %q, state %d",
			buf, offs, o, err, err, fl.StatusCode.Get(buf), e.sc, fl.state)
	}
	if !bytes.Equal(fl.Reason.Get(buf), e.r) {
		t.Errorf("ParseFLine(%q, %d, ..)=[%d, %d(%q)]"+
			"  reason str %q != %q, state %d",
			buf, offs, o, err, err, fl.Reason.Get(buf), e.r, fl.state)
	}
	if !fl.Parsed() {
		t.Errorf("ParseFLine(%q, %d, ..)=[%d, %d(%q)]"+
			"  invalid/unexpected final state %d",
			buf, offs, o, err, err, fl.state)
	}
}

func testParseFLinePieces(t *testing.T, buf []byte, offs int, e *pflERes, n int) {
	var err ErrorHdr
	var fl PFLine
	o := offs
	pieces := rand.Intn(n)
	for i := 0; i < pieces; i++ {
		sz := rand.Intn(len(buf) + 1 - o)
		end := sz + o
		if end < e.offs {
			o, err = ParseFLine(buf[:end], o, &fl)
			if err != ErrHdrMoreBytes {
				t.Errorf("ParseFLine partial (%q, %d, ..)=[%d, %d(%q)] "+
					"  error %s (%q) expected, state %d",
					buf, offs, o, err, err, ErrHdrMoreBytes, ErrHdrMoreBytes,
					fl.state)
			}
			if fl.Parsed() {
				t.Errorf("ParseFLine(%q, %d, ..)=[%d, %d(%q)]"+
					"  invalid/unexpected final state %d while ErrHdrMoreBytes",
					buf, offs, o, err, err, fl.state)
			}
		} else {
			break
		}
	}
	testParseFLineExp(t, buf, o, &fl, e)
}
