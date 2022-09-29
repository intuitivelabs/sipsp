// Copyright 2022 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

package sipsp

import (
	"bytes"
)

// IP4Prefix checks if a []byte string starts with an ipv4 address.
// It will also parse the ip addresses and return it in dst (if not nil).
// It returns true if the string starts with an ipv4 address and false if not;
// an offset pointing where the parsing has stopped (if the whole
// input buffer was parsed it will be equal to len(buf)) and an error value
// which can be used to get more information about the point where the parsing
// stopped.
// The error values are:
//  - ErrHdrOk  -- the input buffer contains only an ip (parse ok)
//  - ErrHdrMoreValues -- candidate ip parsed, but it's followed by
//                        a possible another IP (ends in a digit).
//  - ErrHdrBadChar -- candidate ip parsed, but it's followed by
//                       another non-numeric char
//   -ErrHdrMoreByte  -- input buffer exhausted without finishing parsing the
//                      ip.
//  - ErrHdrBad -- buf[] does not start with an ip address
func IP4Prefix(buf []byte, dst []byte) (bool, int, ErrorHdr) {
	var ip [4]byte
	pos := 0
	digits := 0
	o := 0
	for ; o < len(buf); o++ {
		if buf[o] <= '9' && buf[o] >= '0' {
			digits++
			if digits > 3 || (uint(ip[pos])*10+uint(buf[o]-'0') > 255) {
				// too many digits or value out of range
				if pos < 3 {
					// too few dots => invalid input
					return false, o, ErrHdrBad
				}
				// could be an ip followed by a number, e.g.:
				//  "1.2.3.2540" => 1.2.3.254  or
				//  "1.2.3.350"  => 1.2.3.35  or
				//  "1.2.3.257"  => 1.2.3.25
				if len(dst) > 0 {
					copy(dst, ip[:])
				}
				return true, o, ErrHdrMoreValues // possible more concat. IPs
			}
			ip[pos] = ip[pos]*10 + buf[o] - '0'
		} else if buf[o] == '.' {
			if digits == 0 {
				// last part had no digits (e.g. "1.2.3.." or "1.2..3.4")
				return false, o, ErrHdrBad
			}
			pos++
			if pos > 3 {
				// too many dots
				if len(dst) > 0 {
					copy(dst, ip[:])
				}
				return true, o, ErrHdrBadChar // ip found, but bad char follows
			}
			digits = 0
			ip[pos] = 0
		} else {
			// unknown char
			if pos < 3 || digits == 0 {
				// too soon to be able to get any ip => not ip
				return false, o, ErrHdrBad
			}
			if len(dst) > 0 {
				copy(dst, ip[:])
			}
			return true, o, ErrHdrBadChar // ip found, followed by bad char
		}
	}
	if pos < 3 || digits == 0 {
		// too few dots or last part had no digits => input too small/truncated
		return false, o, ErrHdrMoreBytes
	}
	if len(dst) > 0 {
		copy(dst, ip[:])
	}
	return true, o, ErrHdrOk
}

// ContainsIP4 checks if a []byte string contains an ipv4 address.
// It will also parse the ip addresses and return it in dst (if not nil).
// It returns true if the string contains an ipv4 address, the address
// start offset and length.
func ContainsIP4(buf []byte, dst []byte) (bool, int, int) {
	for i := 0; i < len(buf); {
		d := bytes.IndexByte(buf[i:], '.')
		if d == -1 {
			break // no ip
		}
		dOffs := d + i
		// try ip offset
		offs := i
		if dOffs >= 3 {
			offs = dOffs - 3
		}
		for o := offs; o < dOffs; o++ {
			ok, nxt, _ := IP4Prefix(buf[o:], dst)
			if ok {
				// found ip
				return true, o, nxt
			}
		}
		i = dOffs + 1
	}
	return false, 0, 0
}
