// Copyright 2022 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

package sipsp

import (
	"testing"
)

func TestParseAllURIHdrs(t *testing.T) {

	type expR struct {
		err  ErrorHdr
		n    int // param number
		offs int
	}
	type testCase struct {
		s    string    // param list
		offs int       // offset in s
		f    POptFlags // parsing flags

		eRes expR // expected result
	}

	testCases := [...]testCase{
		{s: "foo=1&bar&to=a%40b.c", f: POptInputEndF,
			eRes: expR{err: ErrHdrEOH,
				n: 3, offs: 20},
		},
		{s: "foo=1&bar&to=a%40b.c", offs: 6, f: POptInputEndF,
			eRes: expR{err: ErrHdrEOH,
				n: 2, offs: 20},
		},
		{s: "foo=1&bar&to=a%40b.c", offs: 29, f: POptInputEndF,
			eRes: expR{err: ErrHdrEOH,
				n: 1, offs: 20},
		},
		{s: "foo=1&bar=???&to=a%40b.c ", f: POptInputEndF | POptTokSpTermF,
			eRes: expR{err: ErrHdrEOH,
				n: 3, offs: 25},
		},
	}

	var hlst URIHdrsLst
	var hbuf [100]URIHdr

	hlst.Init(hbuf[:])
	for i, tc := range testCases {
		offs, n, err := ParseAllURIHdrs([]byte(tc.s), tc.offs, &hlst, tc.f)

		if err != tc.eRes.err {
			t.Errorf("ParseAllURIHdrs(%q, %d, %p, 0x%x) = %d, %d, %d(%s) "+
				" err %d (%s) != expected %d (%s) (test case %d)",
				tc.s, tc.offs, &hlst, tc.f, offs, n, err, err,
				err, err, tc.eRes.err, tc.eRes.err, i+1)
		}
		if hlst.N != tc.eRes.n {
			t.Errorf("ParseAllURIHdrs(%q, %d, %p, 0x%x) = %d, %d, %d(%s) "+
				" param no %d  != expected %d (test case %d)",
				tc.s, tc.offs, &hlst, tc.f, offs, n, err, err,
				hlst.N, tc.eRes.n, i+1)
		}
		if offs != tc.eRes.offs {
			t.Errorf("ParseAllURIHdrs(%q, %d, %p, 0x%x) = %d, %d, %d(%s) "+
				" offs %d  != expected %d (test case %d)",
				tc.s, tc.offs, &hlst, tc.f, offs, n, err, err,
				offs, tc.eRes.offs, i+1)
		}
		hlst.Reset()
	}
}

func TestURIHdrsEq(t *testing.T) {

	type expR struct {
		err ErrorHdr
		res bool
	}
	type testCase struct {
		s1    string // param list 1
		s2    string // param list 2
		offs1 int    // offset in s1
		offs2 int    // offset in s2
		eRes  expR   // expected result
	}

	testCases := [...]testCase{
		{
			s1:   "subject=project%20x&priority=urgent",
			s2:   "priority=urgent&subject=project%20x",
			eRes: expR{err: ErrHdrOk, res: true},
		},
		{
			s1:   "foo=1&bar&transport=tcp&TTL=10&lr",
			s2:   "foo=1&bar&transport=tcp&TTL=10&lr",
			eRes: expR{err: ErrHdrOk, res: true},
		},
		{
			s1:   "foo=1&bar&transport=tcp&TTL=10&lr",
			s2:   "TTL=10&transport=tcp&bar&lr&foo=1",
			eRes: expR{err: ErrHdrOk, res: true},
		},
		{
			s1:   "subject=project%20x&priority=urgent",
			s2:   "",
			eRes: expR{err: ErrHdrOk, res: false},
		},
		{
			s1:   "",
			s2:   "TTL=10&transport=tcp&bar&lr&foo=1",
			eRes: expR{err: ErrHdrOk, res: false},
		},
		{
			s1:   "foo=1&bar&transport=tcp&TTL=10&lr",
			s2:   "TTL=10&transport=tcp",
			eRes: expR{err: ErrHdrOk, res: false},
		},
		{
			s1:   "foo=1&bar&transport=tcp&lr", // no TTL
			s2:   "TTL=10&transport=tcp",
			eRes: expR{err: ErrHdrOk, res: false},
		},
		{
			s1:   "foo=1&bar&transport=tcp&TTL=10&lr",
			s2:   "foo=1&bar&transport=udp&TTL=10&lr", // diff transport
			eRes: expR{err: ErrHdrOk, res: false},
		},
		{
			s1:   "foo=1&bar&transport=tcp&TTL=10&lr",
			s2:   "TTL=10&transport=tcp&bar&lr&foo=2", // diff foo
			eRes: expR{err: ErrHdrOk, res: false},
		},
		{
			s1:   "foo=1&bar=baz&transport=tcp&TTL=10&lr", // diff bar
			s2:   "TTL=10&transport=tcp&bar&lr&foo=1",
			eRes: expR{err: ErrHdrOk, res: false},
		},
	}

	for i, tc := range testCases {
		res, err := URIHdrsEq([]byte(tc.s1), tc.offs1,
			[]byte(tc.s2), tc.offs2)

		if err != tc.eRes.err {
			t.Errorf("URIHdrsEq(%q, %d, %q, %d) = %v,  %d (%s) "+
				" err %d (%s) != expected %d (%s) (test case %d)",
				tc.s1, tc.offs1, tc.s2, tc.offs2, res, err, err,
				err, err, tc.eRes.err, tc.eRes.err, i+1)
		}
		if res != tc.eRes.res {
			t.Errorf("URIHdrsEq(%q, %d, %q, %d) = %v,  %d (%s) "+
				" res %v != expected %v (test case %d)",
				tc.s1, tc.offs1, tc.s2, tc.offs2, res, err, err,
				res, tc.eRes.res, i+1)
		}
	}
}
