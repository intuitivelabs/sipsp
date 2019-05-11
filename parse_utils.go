package sipsp

//skipLWS jumps over white space (including CRLF SP).
// It returns and offset pointing after the white space or
// ErrHdrEOH and the CR offset and length if the end of header was found or
// errHdrMoreBytes and a "continuation" offset if the input buffer
// was exhausted or it is not big enough to allow checking for CRLF SP.
// It accepts also CR SP  or LF SP.
func skipLWS(buf []byte, offs int) (int, int, ErrorHdr) {
	i := offs
	for ; i < len(buf); i++ {
		c := buf[i]
		switch c {
		case ' ', '\t':
			// do nothing
		case '\r', '\n':
			// accept CRLF SP. CR SP and LF SP
			n, crl, err := skipCRLF(buf, i)
			if err == 0 {
				if n >= len(buf) {
					// return current position, the CRLF SP has to be re-tried
					// with more bytes
					return i, 0, ErrHdrMoreBytes
				}
				if buf[n] != ' ' && buf[n] != '\t' {
					return i, crl, ErrHdrEOH
				}
			} else {
				return n, crl, err
			}
			i = n
			/*
				case '\r': //CR
					// look ahead for  LF SP
					if (i + 2) >= len(buf) {
						return i, ErrHdrMoreBytes
					}
					if buf[i+1] == '\n' {
						if buf[i+2] == ' ' || buf[i+2] == '\t' {
							i += 2 // skip over and continue
						} else {
							return i, ErrHdrEOH // end of header, return CR offset
						}
					} else if buf[i+1] == ' ' || buf[i+1] == '\t' {
						// CR SP, accept it (testing, liberal a.s.o.)
						i += 1
					} else {
						return i, ErrHdrEOH // consider this the end of header
					}
				case '\n': //
					// accept also SP* LF SP
					// look ahead for SP
					if (i + 1) >= len(buf) {
						return i, ErrHdrMoreBytes
					}
					if buf[i+1] == ' ' || buf[i+1] == '\t' {
						i++
					} else {
						return i, ErrHdrEOH // consider this the end of header
					}
			*/
		default:
			return i, 0, ErrHdrOk
		}
	}
	// bufer exhausted
	return i, 0, ErrHdrMoreBytes
}

// skipCRLF tries to skip over a CRLF, CR or LF.
// It returns offset immediately after the skipped part (CRLF),
//  an error and the length of the skipped part (2 or 1 on success).
// ErrHdrMoreBytes means there is not enough space in  buf[offs:] to
// check for CRLF.
// It expects a CR or LF at buf[offs] (else ErrHdrNoCr will be returned)
func skipCRLF(buf []byte, offs int) (int, int, ErrorHdr) {
	i := offs
	if i+1 >= len(buf) {
		if (i < len(buf)) && (buf[i] != '\r') && (buf[i] != '\n') {
			return i, 0, ErrHdrNoCR
		}
		return i, 0, ErrHdrMoreBytes
	}
	if buf[i] == '\r' {
		if buf[i+1] == '\n' {
			return i + 2, 2, ErrHdrOk
		}
		// accept also single CR instead of CRLF
		return i + 1, 1, ErrHdrOk
	} else if buf[i] == '\n' { // accept also single LF
		return i + 1, 1, ErrHdrOk
	}
	return i, 0, ErrHdrNoCR
}

// skipWS jumps over white space.
// It stops at the first non-whitespace (' ' , '\t') , CR or LF or at the
// end of the string.
// It returns and offset pointing after the whitespace.
func skipWS(buf []byte, offs int) int {
	for ; offs < len(buf) && (buf[offs] == ' ' || buf[offs] == '\t'); offs++ {
		// empty
	}
	return offs
}

// skipToken jumps over non-white space.
// It stops at the first whitespace (' ' , '\t') , CR or LF or at the
// end of the string.
// It returns and offset pointing after the token.
func skipToken(buf []byte, offs int) int {
	for ; offs < len(buf) &&
		buf[offs] != ' ' &&
		buf[offs] != '\t' &&
		buf[offs] != '\r' &&
		buf[offs] != '\n'; offs++ {
		// empty
	}
	return offs
}

// skipTokenDelim jumps over non-white space and non-delim characters.
// It's similar to skipToken, but adds an extra char delimitator besides the
// whitespace.
// It stops at the first whitespace (' ' , '\t') , delim character, CR or LF
// or at the end of the string.
// It returns and offset pointing after the token.
func skipTokenDelim(buf []byte, offs int, delim byte) int {
	for ; offs < len(buf) &&
		buf[offs] != ' ' &&
		buf[offs] != '\t' &&
		buf[offs] != '\r' &&
		buf[offs] != '\n' &&
		buf[offs] != delim; offs++ {
		// empty
	}
	return offs
}

// skipLine tries to skip over an entire line terminated by CRLF, CR or LF.
// It returns offset immediately after the skipped part (CRLF),
//  the length of the CRLF (2 or 1 on success) and an error.
// ErrHdrMoreBytes means there is not enough space in  buf[offs:] to
// check for CRLF.
// It expects a CR or LF at buf[offs] (else ErrHdrNoCr will be returned)
func skipLine(buf []byte, offs int) (int, int, ErrorHdr) {

	for ; offs < len(buf) && buf[offs] != '\n' && buf[offs] != '\r'; offs++ {
	}
	return skipCRLF(buf, offs)
}
