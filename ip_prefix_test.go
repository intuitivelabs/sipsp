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
		{[]byte("1.2.1113.4"),
			false, 7, ErrHdrBad, [4]byte{0, 0, 0, 0}},
		{[]byte("1.2.256.4"),
			false, 6, ErrHdrBad, [4]byte{0, 0, 0, 0}},
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

func TestIP6Prefix(t *testing.T) {
	type testCase struct {
		t     []byte   // test "string"
		eRes  bool     // expected result
		eOffs int      // expected offset
		eErr  ErrorHdr // expected error
		eIP   [16]byte // expected parsed IP
	}

	tests := [...]testCase{
		{[]byte("1a01:2b02:3c03:4d04:5e05:6f06:7007:8108"),
			true, 39, ErrHdrOk,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("ffff:2b02:3c03:4d04:5e05:f06:07:08"),
			true, 34, ErrHdrOk,
			[16]byte{0xff, 0xff, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0xf, 0x06, 0x00, 0x07, 0x00, 0x08}},
		{[]byte("1a01:2b02:3c03:4d04::6f06:7007:8108"),
			true, 35, ErrHdrOk,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x00, 0x00, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("1a01:2b02:3c03::6f06:7007:8108"),
			true, 30, ErrHdrOk,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x00, 0x00,
				0x00, 0x00, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("1a01:2b02:3c03:4d04::5e05:6f06:7007:8108"),
			true, 40, ErrHdrOk,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("1a01:2b02:3c03:4d04:5e05:6f06:7007::"),
			true, 36, ErrHdrOk,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x00, 0x00}},
		{[]byte("1a01:2b02:3c03:4d04:5e05:6f06::"),
			true, 31, ErrHdrOk,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x00, 0x00, 0x00, 0x00}},
		{[]byte("1a01:2b02:3c03:4d04:5e05::"),
			true, 26, ErrHdrOk,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{[]byte("::2b02:3c03:4d04:5e05:6f06:7007:8108"),
			true, 36, ErrHdrOk,
			[16]byte{0x00, 0x00, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("::5e05:6f06:7007:8108"),
			true, 21, ErrHdrOk,
			[16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("::"),
			true, 2, ErrHdrOk,
			[16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{[]byte("1a01:2b02:3c03:4d04:5e05:6f06:7007:8108X"),
			true, 39, ErrHdrBadChar,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("1a01:2b02:3c03:4d04:5e05:6f06:7007:8108:"),
			true, 39, ErrHdrBadChar,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("1a01:2b02:3c03:4d04:5e05:6f06:7007:81089"),
			true, 39, ErrHdrMoreValues,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("::X"),
			true, 2, ErrHdrBadChar,
			[16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{[]byte("::B"),
			true, 3, ErrHdrOk,
			[16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b}},
		{[]byte("1a01:2b02:3c03:4d04:5e05:6f06:7007:::"),
			true, 36, ErrHdrBadChar,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x00, 0x00}},

		{[]byte("[1a01:2b02:3c03:4d04:5e05:6f06:7007:8108]"),
			true, 41, ErrHdrOk,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("[1a01:2b02:3c03:4d04::6f06:7007:8108]"),
			true, 37, ErrHdrOk,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x00, 0x00, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("[1a01:2b02:3c03::6f06:7007:8108]"),
			true, 32, ErrHdrOk,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x00, 0x00,
				0x00, 0x00, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("[1a01:2b02:3c03:4d04::5e05:6f06:7007:8108]"),
			true, 42, ErrHdrOk,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("[1a01:2b02:3c03:4d04:5e05:6f06:7007::]"),
			true, 38, ErrHdrOk,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x00, 0x00}},
		{[]byte("[1a01:2b02:3c03:4d04:5e05:6f06::]"),
			true, 33, ErrHdrOk,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x00, 0x00, 0x00, 0x00}},
		{[]byte("[1a01:2b02:3c03:4d04:5e05::]"),
			true, 28, ErrHdrOk,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{[]byte("[::2b02:3c03:4d04:5e05:6f06:7007:8108]"),
			true, 38, ErrHdrOk,
			[16]byte{0x00, 0x00, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("[::5e05:6f06:7007:8108]"),
			true, 23, ErrHdrOk,
			[16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("[::]"),
			true, 4, ErrHdrOk,
			[16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{[]byte("[1a01:2b02:3c03:4d04:5e05:6f06:7007:8108]X"),
			true, 41, ErrHdrMoreValues,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("[1a01:2b02:3c03:4d04:5e05:6f06:7007:8108"),
			true, 40, ErrHdrMoreBytes,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},

		{[]byte("[1a01:2b02:3c03:4d04:5e05:6f06:7007:81089]"),
			false, 40, ErrHdrBad,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("[::X]"),
			false, 3, ErrHdrBad,
			[16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{[]byte("[::B]"),
			true, 5, ErrHdrOk,
			[16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b}},
		{[]byte("[1a01:2b02:3c03:4d04:5e05:6f06:7007:::"),
			false, 37, ErrHdrBad,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x00, 0x00}},

		{[]byte(":::"), // tricky, we cannot tell => say it's not an ipv6
			false, 2, ErrHdrBad,
			[16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},

		{[]byte("1a01:2b02:3c03:4d04:5e05:6f06:7007:"),
			false, 35, ErrHdrMoreBytes,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x00, 0x00}},
		{[]byte("1a01:2b02:3c03:4d04:5e05:6f06:7007"),
			false, 34, ErrHdrMoreBytes,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x00, 0x00}},
		{[]byte("1a01:2b02:3c03:Gd04:5e05:6f06:7007:8108"),
			false, 15, ErrHdrBad,
			[16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{[]byte("1a01:2b02:3c03:4d041:5e05:6f06:7007:8108"),
			false, 19, ErrHdrBad,
			[16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{[]byte("1a01:2b02:3c03:::4d04:5e05:6f06:7007:8108"),
			false, 16, ErrHdrBad,
			[16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},

		/*
			{[]byte("1.2.3."),
				false, 6, ErrHdrMoreBytes, [4]byte{0, 0, 0, 0}},
			{[]byte("1.2.3"),
				false, 5, ErrHdrMoreBytes, [4]byte{0, 0, 0, 0}},
			{[]byte("1.a2.3.4"),
				false, 2, ErrHdrBad, [4]byte{0, 0, 0, 0}},
			{[]byte("1.2..3.4"),
				false, 4, ErrHdrBad, [4]byte{0, 0, 0, 0}},
		*/
	}

	var dst = make([]byte, 16)
	for i, tc := range tests {
		res, o, err := IP6Prefix(tc.t, dst)
		if res != tc.eRes {
			t.Errorf("IP6Prefix(%q, ..) for test %d"+
				" returned %v instead of %v",
				string(tc.t), i, res, tc.eRes)
		}
		if o != tc.eOffs {
			t.Errorf("IP6Prefix(%q, ..) for test %d"+
				" returned offs %v instead of %v",
				string(tc.t), i, o, tc.eOffs)
		}
		if err != tc.eErr {
			t.Errorf("IP6Prefix(%q, ..) for test %d"+
				" returned err %d (%s) instead of %d (%s)",
				string(tc.t), i, err, err, tc.eErr, tc.eErr)
		}
		if res && !bytes.Equal(dst, tc.eIP[:]) {
			t.Errorf("IP6Prefix(%q, ..) for test %d"+
				" returned ip %x:%x:%x:%x:%x:%x:%x:%x"+
				" instead  of %x:%x:%x:%x:%x:%x:%x:%x",
				string(tc.t), i,
				uint16(dst[0])<<8|uint16(dst[1]),
				uint16(dst[2])<<8|uint16(dst[3]),
				uint16(dst[4])<<8|uint16(dst[5]),
				uint16(dst[6])<<8|uint16(dst[7]),
				uint16(dst[8])<<8|uint16(dst[9]),
				uint16(dst[10])<<8|uint16(dst[11]),
				uint16(dst[12])<<8|uint16(dst[13]),
				uint16(dst[14])<<8|uint16(dst[15]),
				uint16(tc.eIP[0])<<8|uint16(tc.eIP[1]),
				uint16(tc.eIP[2])<<8|uint16(tc.eIP[3]),
				uint16(tc.eIP[4])<<8|uint16(tc.eIP[5]),
				uint16(tc.eIP[6])<<8|uint16(tc.eIP[7]),
				uint16(tc.eIP[8])<<8|uint16(tc.eIP[9]),
				uint16(tc.eIP[10])<<8|uint16(tc.eIP[11]),
				uint16(tc.eIP[12])<<8|uint16(tc.eIP[13]),
				uint16(tc.eIP[14])<<8|uint16(tc.eIP[15]),
			)
		}
	}
}

func TestContainsIP6(t *testing.T) {
	type testCase struct {
		t     []byte   // test "string"
		eRes  bool     // expected result
		eOffs int      // expected offset
		eLen  int      // expected length
		eIP   [16]byte // expected parsed IP
	}

	tests := [...]testCase{
		{[]byte("1a01:2b02:3c03:4d04:5e05:6f06:7007:8108"),
			true, 0, 39,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("1a01:2b02:3c03:4d04:5e05:6f06:7007:8108X"),
			true, 0, 39,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("1a01:2b02:3c03:4d04:5e05:6f06:7007:8108a"),
			true, 0, 39,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("1a01:2b02:3c03:4d04:5e05:6f06:7007:8108:"),
			true, 0, 39,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("x1a01:2b02:3c03:4d04:5e05:6f06:7007:8108"),
			true, 1, 39,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("xyz1a01:2b02:3c03:4d04:5e05:6f06:7007:8108"),
			true, 3, 39,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("uvxyz1a01:2b02:3c03:4d04:5e05:6f06:7007:8108"),
			true, 5, 39,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("tuvxyz1a01:2b02:3c03:4d04:5e05:6f06:7007:8108"),
			true, 6, 39,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("longtest11a01:2b02:3c03:4d04:5e05:6f06:7007:81082test"),
			true, 9, 39,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("longtest11a01:2b02:3c03:4d04:5e05:6f06:7007::test"),
			true, 9, 36,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x00, 0x00}},

		{[]byte("[1a01:2b02:3c03:4d04:5e05:6f06:7007:8108]"),
			true, 0, 41,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("[1a01:2b02:3c03:4d04:5e05:6f06:7007:8108]x"),
			true, 0, 41,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
		{[]byte("longtest1[1a01:2b02:3c03:4d04:5e05:6f06:7007:8108]2test"),
			true, 9, 41,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},

		{[]byte("longtest11a01:2b02:3c03:4d04:5e05:6f06:7007:test"),
			false, 0, 0,
			[16]byte{0x1a, 0x01, 0x2b, 0x02, 0x3c, 0x03, 0x4d, 0x04,
				0x5e, 0x05, 0x6f, 0x06, 0x70, 0x07, 0x81, 0x08}},
	}

	var dst = make([]byte, 16)
	for i, tc := range tests {
		res, o, l := ContainsIP6(tc.t, dst)
		if res != tc.eRes {
			t.Errorf("ContainsIP6(%q, ..) for test %d"+
				" returned %v instead of %v",
				string(tc.t), i, res, tc.eRes)
		}
		if o != tc.eOffs {
			t.Errorf("ContainsIP6(%q, ..) for test %d"+
				" returned offs %v instead of %v",
				string(tc.t), i, o, tc.eOffs)
		}
		if l != tc.eLen {
			t.Errorf("ContainsIP6(%q, ..) for test %d"+
				" returned len %v instead of %v",
				string(tc.t), i, l, tc.eLen)
		}
		if res && !bytes.Equal(dst, tc.eIP[:]) {
			t.Errorf("ContainsIP6(%q, ..) for test %d"+
				" returned ip %x:%x:%x:%x:%x:%x:%x:%x"+
				" instead  of %x:%x:%x:%x:%x:%x:%x:%x",
				string(tc.t), i,
				uint16(dst[0])<<8|uint16(dst[1]),
				uint16(dst[2])<<8|uint16(dst[3]),
				uint16(dst[4])<<8|uint16(dst[5]),
				uint16(dst[6])<<8|uint16(dst[7]),
				uint16(dst[8])<<8|uint16(dst[9]),
				uint16(dst[10])<<8|uint16(dst[11]),
				uint16(dst[12])<<8|uint16(dst[13]),
				uint16(dst[14])<<8|uint16(dst[15]),
				uint16(tc.eIP[0])<<8|uint16(tc.eIP[1]),
				uint16(tc.eIP[2])<<8|uint16(tc.eIP[3]),
				uint16(tc.eIP[4])<<8|uint16(tc.eIP[5]),
				uint16(tc.eIP[6])<<8|uint16(tc.eIP[7]),
				uint16(tc.eIP[8])<<8|uint16(tc.eIP[9]),
				uint16(tc.eIP[10])<<8|uint16(tc.eIP[11]),
				uint16(tc.eIP[12])<<8|uint16(tc.eIP[13]),
				uint16(tc.eIP[14])<<8|uint16(tc.eIP[15]),
			)
		}
	}
}
