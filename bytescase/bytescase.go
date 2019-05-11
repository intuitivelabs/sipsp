package bytescase

type ErrorConv int32

// possible returned errors
const (
	NoErr ErrorConv = iota
	ErrDstNoSpc
	ErrLast
)

// conversion from error id to string
var ErrStr [ErrLast]string = [...]string{
	"no error",
	"not enough space in dst",
}

// implement the error interface
func (e ErrorConv) Error() string {
	return ErrStr[e]
}

// converts one byte to lower case
func ByteToLower(b byte) byte {
	var m uint32
	/*  if b is upper case => b | 0x20 will be the lower case
	    compute a mask for ORing, m such that m = 0x20 if uppercase
	    and 0 othewise. In the following expression the sign bit
	    will be set only if b is in range. The bit is then shifted to
	    bit 5 position (0x20) and everything else is masked out (& 0x20).
	*/
	m = (((0x40 - uint32(b)) & (uint32(b) - 0x5b)) >> 26) & 0x20
	return b | byte(m)
	//m = (((0x40 - uint32(b)) ^ (0x5a - uint32(b))) >> 26) & 0x20
	//return b ^ byte(m)
}

// converts one byte to lower case
func ByteToUpper(b byte) byte {
	var m uint32
	/*  if b is lower case => b & ^0x20 will be the upper case
	    compute a mask for ORing, m such that m = 0x20 if uppercase
	    and 0 othewise. In the following expression the sign bit
	    will be set only if b is in range. The bit is then shifted to
	    bit 5 position (0x20) and everything else is masked out (& 0x20).
	*/
	m = (((0x60 - uint32(b)) & (uint32(b) - 0x7b)) >> 26) & 0x20
	return b & ^byte(m)
}

// Converts src to lower case and write it in dst.
// Returns error !=nill if not enough space in dst.
func ToLower(src, dst []byte) error {
	if len(dst) < len(src) {
		return ErrDstNoSpc
	}
	var m uint32
	for i, v := range src {
		// compute toLower mask for XORing:
		// check if the sign bit of tje 2 subs are different amd if
		// so create a mask that contains 0x20: xor the substraction
		// results and then shift the sign bit to bit5 (the bit set in 0x20)
		// m = (((0x40 - uint32(v)) ^ (0x5a - uint32(v))) >> 26) & 0x20
		// dst[i] = v ^ byte(m)

		m = (((0x40 - uint32(v)) & (uint32(v) - 0x5b)) >> 26) & 0x20
		dst[i] = v | byte(m)
	}
	return nil
}

// Compares 2 byte slices for equality in case insensitive mode
func CmpEq(s1, s2 []byte) bool {
	if len(s1) != len(s2) {
		return false
	}
	//var m1, m2 uint32
	var m byte
	for i, v := range s1 {
		/* use toLower mask.  but only if v is a char ('A'-'Z', 'a'-'z')
		   =>  if v in [AZaz] m = 0x20 else m = 0 */
		m = byte(((((0x40 - uint32(v)) & (uint32(v) - 0x5b)) /* 'A'-'Z'*/ |
			((0x60 - uint32(v)) & (uint32(v) - 0x7b))) >> 26) & 0x20)
		if v|m != s2[i]|m {
			return false
		}

		// compute toLower masks for the current chars in the 2 strings
		/*
			m1 = (((0x40 - uint32(v)) ^ (0x5a - uint32(v))) >> 26) & 0x20
			m2 = (((0x40 - uint32(s2[i])) ^ (0x5a - uint32(s2[i]))) >> 26) & 0x20
			// check if crt char ^ masks are equal
			if (v ^ byte(m1)) != (s2[i] ^ byte(m2)) {
				return false
			}
		*/
	}
	return true
}

// Checks if s starts with prefix in case insensitive mode.
// Returns an index in s[] pointing after the matched prefix + true on success
// (e.g. len(prefix), true) or an index to the first non-matching
// character in s and false (e.g.: n, false) if the prefix is not fully
// contained in s.
// If s==prefix the returned index will be len(s) and if prefix == [] the
// index will be 0. If prefix is longer then s the return will be 0, false.
func Prefix(prefix, s []byte) (int, bool) {
	var m byte
	plen := len(prefix)
	if plen > len(s) {
		return 0, false
	}
	for i, v := range s {
		if i >= plen {
			return i, true
		}
		// compute  mask for the current chars in the 2 strings
		m = byte(((((0x40 - uint32(v)) & (uint32(v) - 0x5b)) /* 'A'-'Z'*/ |
			((0x60 - uint32(v)) & (uint32(v) - 0x7b))) >> 26) & 0x20)
		// check if crt char ^ masks are equal
		if v|m != prefix[i]|m {
			return i, false
		}
	}
	// prefix fully matched s
	return len(s), true
}
