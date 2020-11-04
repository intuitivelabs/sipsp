// // Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
// //
// // Use of this source code is governed by source-available license
// // that can be found in the LICENSE file in the root of the source
// // tree.

package sipsp

type PCallIDBody struct {
	CallID PField
	PCallIDIState
}

func (cv *PCallIDBody) Reset() {
	*cv = PCallIDBody{}
}

func (cv PCallIDBody) Empty() bool {
	return cv.state == ciInit
}

func (cv PCallIDBody) Parsed() bool {
	return cv.state == ciFIN
}

func (cv PCallIDBody) Pending() bool {
	return cv.state != ciFIN && cv.state != ciInit
}

// PCallIDIState contains ParseCallIDVal internal state info (private).
type PCallIDIState struct {
	state uint8 // internal state
	soffs int   // saved internal offset
}

// internal parser state
const (
	ciInit uint8 = iota
	ciFound
	ciEnd
	ciFIN
)

// ParseCallIDVal parses the value/content of a Callid header.
// The parameters are: a message buffer, the offset in the buffer where the
// from: (or to:) value starts (should point after the ':') and a pointer
// to a from value structure that will be filled.
// It returns a new offset, pointing immediately after the end of the header
// (it could point to len(buf) if the header end the end of the buffer
// coincide) and an error. If the header is not fully contained in buf[offs:]
//  ErrHdrMoreBytes will be returned and this function can be called again
// when more bytes are available, with the same buffer, the returned
// offset ("continue point") and the same pfrom structure.
func ParseCallIDVal(buf []byte, offs int, pcid *PCallIDBody) (int, ErrorHdr) {

	if pcid.state == ciFIN {
		// called again after finishing
		return offs, 0 // or report error?
	}
	i := offs
	var n, crl int // next non lws and crlf length
	var err ErrorHdr
	for i < len(buf) {
		c := buf[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			switch pcid.state {
			case ciFound:
				pcid.CallID.Set(pcid.soffs, i)
				pcid.state = ciEnd
				fallthrough
			case ciInit, ciEnd:
				n, crl, err = skipLWS(buf, i)
				if err == 0 {
					i = n
					continue
				}
				if err == ErrHdrEOH {
					// end of header
					goto endOfHdr
				}
				if err == ErrHdrMoreBytes {
					i = n
					goto moreBytes
				}
				return n, err
			}
			// LWS
		default:
			// almost everything else is valid in a callid
			// (except non-ascii), we allow anything
			switch pcid.state {
			case ciInit:
				pcid.state = ciFound
				pcid.soffs = i
			case ciEnd:
				// error, stuff found after callid end (WS in callid ?)
				return i, ErrHdrBadChar
			}
		}
		i++
	}

moreBytes:
	// end of buffer
	return i, ErrHdrMoreBytes
endOfHdr:
	// here i will point to first WS char (including CR & LF)
	//      n will point to the line end (CR or LF)
	//      crl will contain the line end length (1 or 2) so that
	//      n+crl is the first char in the new header
	switch pcid.state {
	case ciEnd:
		// do nothing
	case ciFound:
		// start found => callid is terminated by CRLF
		pcid.CallID.Set(pcid.soffs, i)
	case ciInit:
		// empty callid
		return n + crl, ErrHdrBad
	default:
		return n + crl, ErrHdrBug
	}
	pcid.state = ciFIN
	pcid.soffs = 0
	return n + crl, 0
}
