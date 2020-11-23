// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipsp

import (
	// fmt"
	"testing"
	//	"log"
)

func TestParseOneContact(t *testing.T) {
	type testCase struct {
		t      []byte    // test "string"
		offs   int       // offset in t
		ePFrom PFromBody // expected parsed contacts, p. value[] ignored
		eOffs  int       // expected offset
		eErr   ErrorHdr  // expected error
	}
	tests := [...]testCase{
		{[]byte("Foo Bar <sip:f@bar.com>;x=y\r\nX"), 0,
			PFromBody{Star: false, Q: 0, Expires: 0,
				Name: PField{0, 8}, URI: PField{9, 13},
				Params: PField{24, 3}, Tag: PField{0, 0}},
			29 /* \r offset */, ErrHdrOk},
		{[]byte("<sip:f@bar.com>;q=1\r\nX"), 0,
			PFromBody{Star: false, Q: 1000, Expires: 0,
				Name: PField{0, 8}, URI: PField{9, 13},
				Params: PField{24, 3}, Tag: PField{0, 0}},
			21 /* \r offset */, ErrHdrOk},
		{[]byte("<sip:f@bar.com>;q=1.00\r\nX"), 0,
			PFromBody{Star: false, Q: 1000, Expires: 0,
				Name: PField{0, 8}, URI: PField{9, 13},
				Params: PField{24, 3}, Tag: PField{0, 0}},
			24 /* \r offset */, ErrHdrOk},
		{[]byte("<sip:f@bar.com>;q=1.000\r\nX"), 0,
			PFromBody{Star: false, Q: 1000, Expires: 0,
				Name: PField{0, 8}, URI: PField{9, 13},
				Params: PField{24, 3}, Tag: PField{0, 0}},
			25 /* \r offset */, ErrHdrOk},
		{[]byte("<sip:f@bar.com>;q=0.001\r\nX"), 0,
			PFromBody{Star: false, Q: 1, Expires: 0,
				Name: PField{0, 8}, URI: PField{9, 13},
				Params: PField{24, 3}, Tag: PField{0, 0}},
			25 /* \r offset */, ErrHdrOk},
		{[]byte("<sip:f@bar.com>;q=0.02\r\nX"), 0,
			PFromBody{Star: false, Q: 20, Expires: 0,
				Name: PField{0, 8}, URI: PField{9, 13},
				Params: PField{24, 3}, Tag: PField{0, 0}},
			24 /* \r offset */, ErrHdrOk},
		{[]byte("<sip:f@bar.com>;q=0.3\r\nX"), 0,
			PFromBody{Star: false, Q: 300, Expires: 0,
				Name: PField{0, 8}, URI: PField{9, 13},
				Params: PField{24, 3}, Tag: PField{0, 0}},
			23 /* \r offset */, ErrHdrOk},
		{[]byte("<sip:f@bar.com>;q=0.987\r\nX"), 0,
			PFromBody{Star: false, Q: 987, Expires: 0,
				Name: PField{0, 8}, URI: PField{9, 13},
				Params: PField{24, 3}, Tag: PField{0, 0}},
			25 /* \r offset */, ErrHdrOk},
		{[]byte("<sip:f@bar.com>;q=1.001\r\nX"), 0,
			PFromBody{Star: false, Q: 0, ParamErr: ErrHdrValBad,
				Name: PField{0, 8}, URI: PField{9, 13},
				Params: PField{24, 3}, Tag: PField{0, 0}},
			25 /* \r offset */, 0},
		{[]byte("<sip:f@bar.com>;q=0.1234\r\nX"), 0,
			PFromBody{Star: false, Q: 0, ParamErr: ErrHdrValTooLong,
				Name: PField{0, 8}, URI: PField{9, 13},
				Params: PField{24, 3}, Tag: PField{0, 0}},
			26 /* \r offset */, 0},
		{[]byte("*\r\nX"), 0,
			PFromBody{Star: true, Q: 0, Expires: 0},
			0 /* \r offset */, ErrHdrOk},
		{[]byte("   *\r\nX"), 0,
			PFromBody{Star: true, Q: 0, Expires: 0, V: PField{3, 1}},
			0 /* \r offset */, ErrHdrOk},
		{[]byte("*	 \r\nX"), 0,
			PFromBody{Star: true, Q: 0, Expires: 0, V: PField{0, 1}},
			0 /* \r offset */, ErrHdrOk},
		{[]byte("	*	 \r\nX"), 0,
			PFromBody{Star: true, Q: 0, Expires: 0, V: PField{1, 1}},
			0 /* \r offset */, ErrHdrOk},
		{[]byte("	\r\n 	*	 \r\nX"), 0,
			PFromBody{Star: true, Q: 0, Expires: 0, V: PField{5, 1}},
			0 /* \r offset */, ErrHdrOk},
		{[]byte("*;expires=0\r\nX"), 0,
			PFromBody{Star: true, Q: 0, Expires: 0},
			1 /* \r offset */, ErrHdrBadChar},
		{[]byte("*,<sip:foo@bar>\r\nX"), 0,
			PFromBody{Star: true, Q: 0, Expires: 0},
			1 /* \r offset */, ErrHdrBadChar},
	}
	var c PFromBody
	for _, tc := range tests {
		/* fix wildcard values */
		if tc.ePFrom.V.Len <= 0 {
			tc.ePFrom.V.Len = OffsT(len(tc.t) - 3) // assume \r\nX ending
		}
		if tc.eOffs <= 0 {
			tc.eOffs = len(tc.t) - 1
		}
		c.Reset()
		o, err := ParseOneContact(tc.t, tc.offs, &c)
		if err != tc.eErr {
			t.Errorf("ParseOneContact(%q, %d, ..)=[%d, %d(%q)] expected error %d (%q)",
				tc.t, tc.offs, o, err, err, tc.eErr, tc.eErr)
		}
		if o != tc.eOffs {
			t.Errorf("ParseOneContact(%q, %d, ..)=[%d, %d(%q)]"+
				" expected offs %d, got %d",
				tc.t, tc.offs, o, err, err, tc.eOffs, o)
		}
		if err != 0 && err != ErrHdrMoreValues {
			continue
		}

		if !c.Parsed() {
			t.Errorf("ParseOneContact(%q, %d, ..)=[%d, %d(%q)]"+
				" not fully parsed -- state: %d",
				tc.t, tc.offs, o, err, err, c.state)
		}
		if c.Type != HdrContact {
			t.Errorf("ParseOneContact(%q, %d, ..)=[%d, %d(%q)]"+
				" Type expected %v got %v",
				tc.t, tc.offs, o, err, err, HdrContact, c.Type)
		}

		if c.Star != tc.ePFrom.Star {
			t.Errorf("ParseOneContact(%q, %d, ..)=[%d, %d(%q)]"+
				" Star expected %v got %v",
				tc.t, tc.offs, o, err, err, tc.ePFrom.Star, c.Star)
		}

		if c.ParamErr != tc.ePFrom.ParamErr {
			t.Errorf("ParseOneContact(%q, %d, ..)=[%d, %d(%q)]"+
				" ParamErr expected %v got %v",
				tc.t, tc.offs, o, err, err, tc.ePFrom.ParamErr, c.ParamErr)
			continue
		}
		if c.Expires != tc.ePFrom.Expires {
			t.Errorf("ParseOneContact(%q, %d, ..)=[%d, %d(%q)]"+
				" expires expected %v got %v",
				tc.t, tc.offs, o, err, err, tc.ePFrom.Expires, c.Expires)
		}
		if c.Q != tc.ePFrom.Q {
			t.Errorf("ParseOneContact(%q, %d, ..)=[%d, %d(%q)]"+
				" q expected %v got %v",
				tc.t, tc.offs, o, err, err, tc.ePFrom.Q, c.Q)
		}

		if c.V.Offs != tc.ePFrom.V.Offs ||
			c.V.Len != tc.ePFrom.V.Len {
			t.Errorf("ParseOneContact(%q, %d, ..)=[%d, %d(%q)] "+
				"expected V{%d, %d} got {%d, %d}",
				tc.t, tc.offs, o, err, err,
				tc.ePFrom.V.Offs, tc.ePFrom.V.Len,
				c.V.Offs, c.V.Len)
		}
	}
}

func TestParseAllContactsValues(t *testing.T) {
	type testCase struct {
		t          []byte    // test "string"
		offs       int       // offset in t
		ePContacts PContacts // expected parsed contacts, p. value[] ignored
		eOffs      int       // expected offset
		eErr       ErrorHdr  // expected error
	}
	tests := [...]testCase{
		{[]byte("Foo Bar <sip:f@bar.com>;x=y\r\nX"), 0,
			PContacts{N: 1, MaxExpires: 0, MinExpires: 0,
				LastHVal: PField{0, 27}},
			29 /* \r offset */, ErrHdrOk},
		{[]byte("Foo Bar <sip:f@bar.com>;expires=10;q=0.92\r\nX"),
			0,
			PContacts{N: 1, MaxExpires: 10, MinExpires: 10,
				LastHVal: PField{0, 0}},
			0 /* \r offset */, ErrHdrOk},
		{[]byte("Foo Bar <sip:f@bar.com>;expires=1,sip:test@foo.bar\r\nX"),
			0,
			PContacts{N: 2, MaxExpires: 1, MinExpires: 0,
				LastHVal: PField{0, 0}},
			0 /* \r offset */, ErrHdrOk},
		{[]byte("C1 <sip:1@ba.b>;expires=1;q=1.0,sip:2@foo.bar;expires=3;q=0.9,<sip:3@c.d>;q=0.123;expires=5;x\r\nX"),
			0,
			PContacts{N: 3, MaxExpires: 5, MinExpires: 1,
				LastHVal: PField{0, 0}},
			0 /* \r offset */, ErrHdrOk},
	}
	var c PContacts
	// try with different parsed contacts array sizes
	for maxc := 0; maxc < 5; maxc++ {
		if maxc == 0 {
			c.Init(nil)
		} else {
			c.Init(make([]PFromBody, maxc))
		}
		for _, tc := range tests {
			/* fix wildcard values */
			if tc.ePContacts.LastHVal.Len <= 0 {
				tc.ePContacts.LastHVal.Len = OffsT(len(tc.t) - 3) // assume \r\nX ending
			}
			if tc.eOffs <= 0 {
				tc.eOffs = len(tc.t) - 1
			}
			o, err := ParseAllContactValues(tc.t, tc.offs, &c)
			if err != tc.eErr {
				t.Errorf("ParseAllContacts(%q, %d, ..)=[%d, %d(%q)] expected error %d (%q)",
					tc.t, tc.offs, o, err, err, tc.eErr, tc.eErr)
			}
			if o != tc.eOffs {
				t.Errorf("ParseAllContacts(%q, %d, ..)=[%d, %d(%q)] expected offs %d",
					tc.t, tc.offs, o, err, err, tc.eOffs)
			}

			if c.N != tc.ePContacts.N {
				t.Errorf("ParseAllContacts(%q, %d, ..)=[%d, %d(%q)] "+
					"expected N %d got %d",
					tc.t, tc.offs, o, err, err, tc.ePContacts.N, c.N)
			}
			if c.MaxExpires != tc.ePContacts.MaxExpires {
				t.Errorf("ParseAllContacts(%q, %d, ..)=[%d, %d(%q)] "+
					"expected MaxExpires %d got %d",
					tc.t, tc.offs, o, err, err,
					tc.ePContacts.MaxExpires, c.MaxExpires)
			}
			if c.MinExpires != tc.ePContacts.MinExpires {
				t.Errorf("ParseAllContacts(%q, %d, ..)=[%d, %d(%q)] "+
					"expected MinExpires %d got %d",
					tc.t, tc.offs, o, err, err,
					tc.ePContacts.MinExpires, c.MinExpires)
			}
			if c.LastHVal.Offs != tc.ePContacts.LastHVal.Offs ||
				c.LastHVal.Len != tc.ePContacts.LastHVal.Len {
				t.Errorf("ParseAllContacts(%q, %d, ..)=[%d, %d(%q)] "+
					"expected LastHval{%d, %d} got {%d, %d}",
					tc.t, tc.offs, o, err, err,
					tc.ePContacts.LastHVal.Offs, tc.ePContacts.LastHVal.Len,
					c.LastHVal.Offs, c.LastHVal.Len)
			}
			if c.VNo() > maxc {
				t.Errorf("ParseAllContacts(%q, %d, ..)=[%d, %d(%q)] "+
					"expected %d <= %d ",
					tc.t, tc.offs, o, err, err, c.VNo(), c.N)
			}
			if c.VNo() != maxc && c.VNo() != c.N {
				t.Errorf("ParseAllContacts(%q, %d, ..)=[%d, %d(%q)] "+
					"expected %d == %d or %d ",
					tc.t, tc.offs, o, err, err, c.VNo(), maxc, c.N)
			}
			c.Reset()
		}
	}
}
