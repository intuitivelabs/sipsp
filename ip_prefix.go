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

// IP6Prefix checks if a []byte string starts with an ipv6 address.
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
//
// It supports "::" in the address and  addresses optionally enclosed in [].
// It does not support yet dual IPv6 + IPv4 format (e.g.: 2001:abcd::1.2.3.4).
func IP6Prefix(buf []byte, dst []byte) (bool, int, ErrorHdr) {
	var addrBuf1 [8]uint16
	var addrBuf2 [8]uint16
	var i, i1 int // current index in addr & saved index addrBuf1
	var colonsNo int
	var foundColon bool
	var digits int // hex digits number for the current ipv6 part
	var bracketSt, bracketEnd bool

	res := true
	err := ErrHdrOk
	addr := &addrBuf1
	o := 0
	// check if it's enclosed in []
	if len(buf) > 1 && buf[0] == '[' {
		o++
		bracketSt = true
	}
	for ; o < len(buf); o++ {
		if buf[o] == ':' {
			colonsNo++
			if colonsNo > 7 {
				// too many colons
				// valid case: 1:2:3:4:5:6:7:: -> 8 colons
				//        or   ::2:3:4:5:6:7:8 -> 8 colons
				// error only if more then 8 colons or
				//  8 colons no double colon found so far and the current
				//  colon is not the last part of a double colon (ending in ::)
				if colonsNo > 8 ||
					(addr != &addrBuf2 && !foundColon) {
					err = ErrHdrBadChar // found ip candidate, but extra ':'
					goto end
				}
			}
			if foundColon { // last char was a colon too
				// double colon (::) -> switch to second result array
				// for the rest
				i1 = i
				i = 0
				if addr == &addrBuf2 {
					// too many double colons (already found one)
					return false, o, ErrHdrBad
				}
				addr = &addrBuf2
			} else {
				foundColon = true
				i++ // next output digit group / array cell
				digits = 0
			}
		} else if v := hexDigToI(buf[o]); v >= 0 {
			foundColon = false
			digits++
			if digits > 4 {
				// too many hex digits
				err = ErrHdrMoreValues // possible more concat IP6
				break
			}
			addr[i] = addr[i]<<4 + uint16(v)
		} else {
			if bracketSt && buf[o] == ']' {
				bracketEnd = true
				break
			}
			// unknown char -> possible end or error
			err = ErrHdrBadChar
			break
		}
	}
	if !foundColon {
		// not ending in ':'
		i++
	}
end:
	if digits == 0 && !foundColon {
		// ending in ":"
		res = false
		if !bracketEnd {
			err = ErrHdrMoreBytes // truncated
		} else {
			err = ErrHdrBad // bracket closed => bad ip
		}
	}
	// if address contain a double colon fix it
	if addr == &addrBuf2 {
		// start in addrBuf1, end in addBuf2 and the middle filled with 0
		rest := 8 - i - i1
		copy(addrBuf1[i1+rest:], addrBuf2[:i])
	} else {
		// no double colons inside
		if colonsNo < 7 || digits == 0 {
			// too few colons or last part had no digits => error
			if err != ErrHdrOk || bracketEnd {
				return false, o, ErrHdrBad // too short and followed by char
			}
			return false, o, ErrHdrMoreBytes
		}
	}
	if len(dst) >= 16 {
		for j := 0; j < 8; j++ {
			dst[j*2] = byte(addrBuf1[j] >> 8)
			dst[j*2+1] = byte(addrBuf1[j] & 0xff)
		}
	}
	if err == ErrHdrOk {
		if bracketSt {
			if bracketEnd {
				o++ // skip over end bracket
				if o < len(buf) {
					err = ErrHdrMoreValues
				}
			} else {
				err = ErrHdrMoreBytes // needs closing brakcet
			}
		} else if bracketEnd {
			err = ErrHdrBadChar
		}
	} else if err == ErrHdrMoreValues {
		if bracketSt && !bracketEnd {
			err = ErrHdrBad
			res = false
		}
	} else if err == ErrHdrBadChar && bracketSt {
		err = ErrHdrBad
		res = false
	}
	return res, o, err
}

// ContainsIP6 checks if a []byte string contains an ipv6 address.
// It will also parse the ip addresses and return it in dst (if not nil).
// It returns true if the string contains an ipv6 address, the address
// start offset and length.
func ContainsIP6(buf []byte, dst []byte) (bool, int, int) {
	for i := 0; i < len(buf); {
		d := bytes.IndexByte(buf[i:], ':')
		if d == -1 {
			break // no ip
		}
		dOffs := d + i
		// try ip offset
		offs := i
		if dOffs >= 5 {
			offs = dOffs - 5 // 4 chars ipv6 segment + optional '['
		}
		for o := offs; o < dOffs; o++ {
			ok, nxt, _ := IP6Prefix(buf[o:], dst)
			if ok {
				// found ip
				return true, o, nxt
			}
		}
		i = dOffs + 1
	}
	return false, 0, 0
}
