package bytescase

/* Functions to test against (used only when testing).
These are needed because go bytes equivalent functions work with
unicode and we need pure ascii versions.
No function is exported.
*/

// converts one byte to lower case
func tByteToLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

// converts one byte to upper case
func tByteToUpper(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - 32
	}
	return b
}

// Converts src to lower case and write it in dst.
// Returns error !=nill if not enough space in dst.
func tToLower(src, dst []byte) error {
	if len(dst) < len(src) {
		return ErrDstNoSpc
	}
	for i, v := range src {
		dst[i] = tByteToLower(v)
	}
	return nil
}

// Compares 2 byte slices for equality in case insensitive mode
func tCmpEq(s1, s2 []byte) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i, v := range s1 {
		if tByteToLower(v) != tByteToLower(s2[i]) {
			return false
		}
	}
	return true
}

// Checks if s starts with prefix in case insensitive mode.
// Returns an index pointing after the matched prefix in s + true or
// ( idx_nomatch, false ). On full match (s==prefix) the returned index
// will be len(s)
func tPrefix(s, prefix []byte) (int, bool) {
	plen := len(prefix)
	for i, v := range s {
		if i >= plen {
			return i, true
		}
		if tByteToLower(v) != tByteToLower(prefix[i]) {
			return i, false
		}
	}
	// prefix fully matched s
	return len(s), true
}
