// Copyright 2021 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

package sipsp

var hex2int8 [128]int8

func init() {
	for i := 0; i < len(hex2int8); i++ {
		if i >= '0' && i <= '9' {
			hex2int8[i] = int8(i - '0')
		} else if i >= 'A' && i <= 'F' {
			hex2int8[i] = int8(i-'A') + 10
		} else if i >= 'a' && i <= 'f' {
			hex2int8[i] = int8(i-'a') + 10
		} else {
			hex2int8[i] = -1
		}
	}
}

// value >=0 on success, <0 on failure
func hexDigToI(c byte) int {
	return int(hex2int8[c&0x7f] | int8(c&0x80))
}

// returns uint64 conversion and true on success, or false on error
func hexToU(b []byte) (uint64, bool) {
	var res uint64

	if len(b) == 0 {
		return 0, false
	}
	for _, d := range b {
		v := hexDigToI(d)
		if v < 0 {
			return res, false
		}
		res = (res << 4) + uint64(v)
	}
	return res, true
}

// returns int64 conversion and true on success, or false on error
func hexToI(b []byte) (int64, bool) {
	if len(b) > 0 && b[0] == '-' {
		r, ok := hexToU(b[1:])
		return -int64(r), ok
	}
	r, ok := hexToU(b)
	return int64(r), ok
}
