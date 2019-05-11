package sipsp

/* number size as string (more then 10 overflows and uint32
more then 9  might */
const MaxCSeqNValueSize = 10
const MaxCSeqNValue = 1<<32 - 1 // numeric max.

type PCSeqBody struct {
	CSeqNo   uint32
	MethodNo SIPMethod
	CSeq     PField
	Method   PField
	V        PField // whole body, trimmed
	PCSeqIState
}

func (cs *PCSeqBody) Reset() {
	*cs = PCSeqBody{}
}

func (cs PCSeqBody) Empty() bool {
	return cs.state == csInit
}

func (cs PCSeqBody) Parsed() bool {
	return cs.state == csFIN
}

func (cs PCSeqBody) Pending() bool {
	return cs.state != csFIN && cs.state != csInit
}

// PCSeqIState contains ParseCLenVal internal state info (private).
type PCSeqIState struct {
	state uint8 // internal state
	soffs int   // saved internal offset
}

// internal parser state
const (
	csInit uint8 = iota
	csFoundDigit
	csEndDigit
	csFoundMethod
	csEnd
	csFIN
)

// ParseCSeqVal parses the value/content of a CSeq header.
// The parameters are: a message buffer, the offset in the buffer where the
// from: (or to:) value starts (should point after the ':') and a pointer
// to a from value structure that will be filled.
// It returns a new offset, pointing immediately after the end of the header
// (it could point to len(buf) if the header end the end of the buffer
// coincide) and an error. If the header is not fully contained in buf[offs:]
//  ErrHdrMoreBytes will be returned and this function can be called again
// when more bytes are available, with the same buffer, the returned
// offset ("continue point") and the same pfrom structure.
func ParseCSeqVal(buf []byte, offs int, pcs *PCSeqBody) (int, ErrorHdr) {

	if pcs.state == csFIN {
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
			switch pcs.state {
			case csFoundDigit, csFoundMethod:
				if pcs.state == csFoundDigit {
					pcs.CSeq.Set(pcs.soffs, i)
					pcs.V.Set(pcs.soffs, i)
					pcs.state = csEndDigit
				} else {
					pcs.Method.Set(pcs.soffs, i)
					pcs.V.Extend(i)
					pcs.state = csEnd
				}
				fallthrough
			case csInit, csEndDigit, csEnd:
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
			switch pcs.state {
			case csInit:
				pcs.state = csFoundDigit
				pcs.soffs = i
				pcs.CSeqNo = uint32(c - '0')
			case csFoundDigit:
				v := pcs.CSeqNo*10 + uint32(c-'0')
				if pcs.CSeqNo > v {
					// overflow
					return i, ErrHdrNumTooBig
				}
				pcs.CSeqNo = v
			case csEndDigit:
				pcs.state = csFoundMethod // method starting with a number(!)
				pcs.soffs = i
			case csFoundMethod: // method containing numners (!)
				// do nothing
			case csEnd:
				// error, stuff found after method end (WS in method ?)
				return i, ErrHdrBadChar
			}
		default:
			// non-number, could be method (we accept anything)
			switch pcs.state {
			case csInit, csFoundDigit:
				// non-number when number expected => error
				return i, ErrHdrBadChar
			case csEndDigit:
				pcs.state = csFoundMethod
				pcs.soffs = i
			case csFoundMethod: // do nothing
			case csEnd:
				// error, stuff found after method end (WS in method ?)
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
	switch pcs.state {
	case csEnd:
		// do nothing
	case csFoundMethod:
		// method start found => method is terminated by CRLF
		pcs.Method.Set(pcs.soffs, i)
		pcs.V.Extend(i)
	case csInit, csFoundDigit, csEndDigit:
		// empty cseq, or terminated before a method was found
		return n + crl, ErrHdrBad
	default:
		return n + crl, ErrHdrBug
	}
	pcs.state = csFIN
	if pcs.CSeq.Len > MaxCSeqNValueSize || pcs.CSeqNo > MaxCSeqNValue {
		return /*n + crl*/ int(pcs.CSeq.Offs), ErrHdrNumTooBig
	}
	pcs.soffs = 0
	pcs.MethodNo = GetMethodNo(pcs.Method.Get(buf))
	return n + crl, 0
}
