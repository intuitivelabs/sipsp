// Copyright 2022 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

package sipsp

import (
	"testing"
)

func TestURIParamResolve(t *testing.T) {
	type testCase struct {
		n    string // param name
		eRes URIParamF
	}

	testCases := [...]testCase{
		{n: "transport", eRes: URIParamTransportF},
		{n: "tRanSpoRT", eRes: URIParamTransportF},
		{n: "USER", eRes: URIParamUserF},
		{n: "methOD", eRes: URIParamMethodF},
		{n: "ttl", eRes: URIParamTTLF},
		{n: "maddr", eRes: URIParamMaddrF},
		{n: "lr", eRes: URIParamLRF},
		{n: "LR", eRes: URIParamLRF},
		{n: "other", eRes: URIParamOtherF},
	}

	for _, tc := range testCases {
		res := URIParamResolve([]byte(tc.n))
		if res != tc.eRes {
			t.Errorf("URIParamResolve(%q) = 0x%x != expecte 0x%x",
				tc.n, res, tc.eRes)
		}
	}
}

func TestParseAllURIParams(t *testing.T) {

	type expR struct {
		err   ErrorHdr
		types URIParamF // param types
		n     int       // param number
		offs  int
	}
	type testCase struct {
		s    string    // param list
		offs int       // offset in s
		f    POptFlags // parsing flags

		eRes expR // expected result
	}

	testCases := [...]testCase{
		{s: "foo=1;bar;transport=tcp;TTL=10;lr", f: POptInputEndF,
			eRes: expR{err: ErrHdrEOH,
				types: URIParamOtherF | URIParamTransportF | URIParamTTLF |
					URIParamLRF,
				n: 5, offs: 33},
		},
		{s: "foo=1;bar;transport=tcp;TTL=10;lr", offs: 6, f: POptInputEndF,
			eRes: expR{err: ErrHdrEOH,
				types: URIParamOtherF | URIParamTransportF | URIParamTTLF |
					URIParamLRF,
				n: 4, offs: 33},
		},
		{s: "foo=1;bar;transport=tcp;TTL=10;lr", offs: 24, f: POptInputEndF,
			eRes: expR{err: ErrHdrEOH,
				types: URIParamTTLF | URIParamLRF,
				n:     2, offs: 33},
		},
		{s: "transport=udp;other=&amp_test?hdr1", offs: 0,
			f: POptTokURIParamF | POptInputEndF,
			eRes: expR{err: ErrHdrOk,
				types: URIParamOtherF | URIParamTransportF,
				n:     2, offs: 32},
		},
		{s: "transport=udp;other?hdr1", offs: 0,
			f: POptTokQmTermF,
			eRes: expR{err: ErrHdrOk,
				types: URIParamOtherF | URIParamTransportF,
				n:     2, offs: 19},
		},
	}

	var plst URIParamsLst
	var pbuf [100]URIParam

	plst.Init(pbuf[:])
	for i, tc := range testCases {
		offs, n, err := ParseAllURIParams([]byte(tc.s), tc.offs, &plst, tc.f)

		if err != tc.eRes.err {
			t.Errorf("ParseAllURIParams(%q, %d, %p, 0x%x) = %d, %d, %d(%s) "+
				" err %d (%s) != expected %d (%s) (test case %d)",
				tc.s, tc.offs, &plst, tc.f, offs, n, err, err,
				err, err, tc.eRes.err, tc.eRes.err, i+1)
		}
		plst.Reset()
	}
}
