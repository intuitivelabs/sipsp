// Copyright 2022 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

package sipsp

import (
	"bytes"
	"testing"
)

func TestIP4Prefix(t *testing.T) {
	type testCase struct {
		t     []byte   // test "string"
		eRes  bool     // expected result
		eOffs int      // expected offset
		eErr  ErrorHdr // expected error
		eIP   [4]byte  // expected parsed IP
	}

	tests := [...]testCase{
		{[]byte("1.2.3.4"),
			true, 7, ErrHdrOk, [4]byte{1, 2, 3, 4}},
		{[]byte("10.20.30.40"),
			true, 11, ErrHdrOk, [4]byte{10, 20, 30, 40}},
		{[]byte("111.112.113.114"),
			true, 15, ErrHdrOk, [4]byte{111, 112, 113, 114}},
		{[]byte("255.255.255.255"),
			true, 15, ErrHdrOk, [4]byte{255, 255, 255, 255}},
		{[]byte("1.2.3.4a"),
			true, 7, ErrHdrBadChar, [4]byte{1, 2, 3, 4}},
		{[]byte("1.2.3.4."),
			true, 7, ErrHdrBadChar, [4]byte{1, 2, 3, 4}},
		{[]byte("1.2.3.401"),
			true, 8, ErrHdrMoreValues, [4]byte{1, 2, 3, 40}},
		{[]byte("1.2.3.1100"),
			true, 9, ErrHdrMoreValues, [4]byte{1, 2, 3, 110}},

		{[]byte("1.2.3."),
			false, 6, ErrHdrMoreBytes, [4]byte{0, 0, 0, 0}},
		{[]byte("1.2.3"),
			false, 5, ErrHdrMoreBytes, [4]byte{0, 0, 0, 0}},
		{[]byte("1.a2.3.4"),
			false, 2, ErrHdrBad, [4]byte{0, 0, 0, 0}},
		{[]byte("1.2..3.4"),
			false, 4, ErrHdrBad, [4]byte{0, 0, 0, 0}},
	}

	var dst = make([]byte, 4)
	for i, tc := range tests {
		res, o, err := IP4Prefix(tc.t, dst)
		if res != tc.eRes {
			t.Errorf("IP4Prefix(%q, ..) for test %d"+
				" returned %v instead of %v",
				string(tc.t), i, res, tc.eRes)
		}
		if o != tc.eOffs {
			t.Errorf("IP4Prefix(%q, ..) for test %d"+
				" returned offs %v instead of %v",
				string(tc.t), i, o, tc.eOffs)
		}
		if err != tc.eErr {
			t.Errorf("IP4Prefix(%q, ..) for test %d"+
				" returned err %d (%s) instead of %d (%s)",
				string(tc.t), i, err, err, tc.eErr, tc.eErr)
		}
		if res && !bytes.Equal(dst, tc.eIP[:]) {
			t.Errorf("IP4Prefix(%q, ..) for test %d"+
				" returned ip %d.%d.%d.%d instead of %d.%d.%d.%d",
				string(tc.t), i, dst[0], dst[1], dst[2], dst[3],
				tc.eIP[0], tc.eIP[1], tc.eIP[2], tc.eIP[3])
		}
	}
}

func TestContainsIP4(t *testing.T) {
	type testCase struct {
		t     []byte  // test "string"
		eRes  bool    // expected result
		eOffs int     // expected offset
		eLen  int     // expected length
		eIP   [4]byte // expected parsed IP
	}

	tests := [...]testCase{
		{[]byte("1.2.3.4"),
			true, 0, 7, [4]byte{1, 2, 3, 4}},
		{[]byte("10.20.30.40"),
			true, 0, 11, [4]byte{10, 20, 30, 40}},
		{[]byte("111.112.113.114"),
			true, 0, 15, [4]byte{111, 112, 113, 114}},
		{[]byte("255.255.255.255"),
			true, 0, 15, [4]byte{255, 255, 255, 255}},
		{[]byte("1.2.3.4a"),
			true, 0, 7, [4]byte{1, 2, 3, 4}},
		{[]byte("1.2.3.4."),
			true, 0, 7, [4]byte{1, 2, 3, 4}},
		{[]byte("1.2.3.401"),
			true, 0, 8, [4]byte{1, 2, 3, 40}},
		{[]byte("1.2.3.1100"),
			true, 0, 9, [4]byte{1, 2, 3, 110}},

		{[]byte("1.2.3."),
			false, 0, 0, [4]byte{0, 0, 0, 0}},
		{[]byte("1.2.3"),
			false, 0, 0, [4]byte{0, 0, 0, 0}},
		{[]byte("1.a2.3.4"),
			false, 0, 0, [4]byte{0, 0, 0, 0}},
		{[]byte("1.2..3.4"),
			false, 0, 0, [4]byte{0, 0, 0, 0}},

		{[]byte("xA1.2.3.4"),
			true, 2, 7, [4]byte{1, 2, 3, 4}},
		{[]byte("c10.20.30.40"),
			true, 1, 11, [4]byte{10, 20, 30, 40}},
		{[]byte("xyz111.112.113.114"),
			true, 3, 15, [4]byte{111, 112, 113, 114}},
		{[]byte("test255.255.255.255test"),
			true, 4, 15, [4]byte{255, 255, 255, 255}},
		{[]byte("6.7.8a1.2.3.4a"),
			true, 6, 7, [4]byte{1, 2, 3, 4}},
		{[]byte("5.6.7..1.2.3.4."),
			true, 7, 7, [4]byte{1, 2, 3, 4}},
		{[]byte("541.2.3.401"),
			true, 1, 9, [4]byte{41, 2, 3, 40}},
		{[]byte("abcde1.2.3.11005.6.7.8"),
			true, 5, 9, [4]byte{1, 2, 3, 110}},

		{[]byte("a1.2.3."),
			false, 0, 0, [4]byte{0, 0, 0, 0}},
		{[]byte("abcde1.2.3"),
			false, 0, 0, [4]byte{0, 0, 0, 0}},
		{[]byte("5.6.1.a2.3.4"),
			false, 0, 0, [4]byte{0, 0, 0, 0}},
		{[]byte("abc5.1.2..3.4"),
			false, 0, 0, [4]byte{0, 0, 0, 0}},
	}

	var dst = make([]byte, 4)
	for i, tc := range tests {
		res, o, l := ContainsIP4(tc.t, dst)
		if res != tc.eRes {
			t.Errorf("ContainsIP4(%q, ..) for test %d"+
				" returned %v instead of %v",
				string(tc.t), i, res, tc.eRes)
		}
		if o != tc.eOffs {
			t.Errorf("ContainsIP4(%q, ..) for test %d"+
				" returned offs %v instead of %v",
				string(tc.t), i, o, tc.eOffs)
		}
		if l != tc.eLen {
			t.Errorf("ContainsIP4(%q, ..) for test %d"+
				" returned len %v instead of %v",
				string(tc.t), i, l, tc.eLen)
		}
		if res && !bytes.Equal(dst, tc.eIP[:]) {
			t.Errorf("ContainsIP4(%q, ..) for test %d"+
				" returned ip %d.%d.%d.%d instead of %d.%d.%d.%d",
				string(tc.t), i, dst[0], dst[1], dst[2], dst[3],
				tc.eIP[0], tc.eIP[1], tc.eIP[2], tc.eIP[3])
		}
	}
}
