// // Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
// //
// // Use of this source code is governed by source-available license
// // that can be found in the LICENSE file in the root of the source
// // tree.

package sipsp

// MaxCLenValueSize holds the maximum length of the Content-Length value
// interpreted as string (more then 9 can overflow and uint32).
const MaxCLenValueSize = 9

// MaxClenValue holds the maximum numeric value for the Content-Length.
const MaxClenValue = 1 << 24 // numeric max.

// PUIntBody holds a partial or fully parsed unsigned int header value.
type PUIntBody struct {
	UIVal uint32
	SVal  PField
	PUIntIState
}

// Reset re-initializes the parsed value and internal parsing state.
func (cl *PUIntBody) Reset() {
	*cl = PUIntBody{}
}

// Empty returns true if nothing was parsed yet.
func (cl PUIntBody) Empty() bool {
	return cl.state == clInit
}

// Parsed returns true if the value is fully parsed.
func (cl PUIntBody) Parsed() bool {
	return cl.state == clFIN
}

// Pending returns true if the value is only partially parsed
// (more input needed).
func (cl PUIntBody) Pending() bool {
	return cl.state != clFIN && cl.state != clInit
}

// PUIntIState contains ParseUIntVal internal state info (private).
type PUIntIState struct {
	state uint8 // internal state
	soffs int   // saved internal offset
}

// internal parser state
const (
	clInit uint8 = iota
	clFound
	clEnd
	clFIN
)

// ParseCLenVal parses a Content-Length header value, starting at offs
// in buf and filling pcl.
// It returns a new offset pointing after the part that was parsed and
// an error.
// For more information see ParseUIntVal().
func ParseCLenVal(buf []byte, offs int, pcl *PUIntBody) (int, ErrorHdr) {
	o, err := ParseUIntVal(buf, offs, pcl)
	if err == 0 &&
		(pcl.SVal.Len > MaxCLenValueSize || pcl.UIVal > MaxClenValue) {
		return int(pcl.SVal.Offs), ErrHdrNumTooBig
	}
	return o, err
}

// ParseUIntVal parses the value/content of a header containing an uint
// (e.g. Content-Length, Expires)
// The parameters are: a message buffer, the offset in the buffer where the
// from: (or to:) value starts (should point after the ':') and a pointer
// to a from value structure that will be filled.
// It returns a new offset, pointing immediately after the end of the header
// (it could point to len(buf) if the header end the end of the buffer
// coincide) and an error. If the header is not fully contained in buf[offs:]
//  ErrHdrMoreBytes will be returned and this function can be called again
// when more bytes are available, with the same buffer, the returned
// offset ("continue point") and the same pfrom structure.
func ParseUIntVal(buf []byte, offs int, pcl *PUIntBody) (int, ErrorHdr) {

	if pcl.state == clFIN {
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
			switch pcl.state {
			case clFound:
				pcl.SVal.Set(pcl.soffs, i)
				pcl.state = clEnd
				fallthrough
			case clInit, clEnd:
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
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			// only numbers are valid inside a content-length header
			switch pcl.state {
			case clInit:
				pcl.state = clFound
				pcl.soffs = i
				pcl.UIVal = uint32(c - '0')
			case clFound:
				v := pcl.UIVal*10 + uint32(c-'0')
				if pcl.UIVal > v {
					// overflow
					return i, ErrHdrNumTooBig
				}
				pcl.UIVal = v
			case clEnd:
				// error, stuff found after callid end (WS in callid ?)
				return i, ErrHdrBadChar
			}
		default:
			// non-number, non whitespace => error
			return i, ErrHdrBadChar
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
	switch pcl.state {
	case clEnd:
		// do nothing
	case clFound:
		// start found => callid is terminated by CRLF
		pcl.SVal.Set(pcl.soffs, i)
	case clInit:
		// empty callid
		return n + crl, ErrHdrBad
	default:
		return n + crl, ErrHdrBug
	}
	pcl.state = clFIN
	pcl.soffs = 0
	return n + crl, 0
}
