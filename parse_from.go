package sipsp

import (
	//"fmt"

	"andrei/sipsp/bytescase"
)

type PFromBody struct {
	Name   PField
	URI    PField
	Tag    PField
	Params PField
	V      PField // complete value, trimmed
	PFromIState
}

func (fv *PFromBody) Reset() {
	*fv = PFromBody{}
}

func (fv *PFromBody) Empty() bool {
	return fv.state == fbInit
}

func (fv *PFromBody) Parsed() bool {
	return fv.state == fbFIN
}

func (fv *PFromBody) Pending() bool {
	return fv.state != fbFIN && fv.state != fbInit
}

// PFromIState contains ParseFrom internal state info (private).
type PFromIState struct {
	state  uint8 // internal state
	soffs  int   // saved internal offset
	pstart int   // current param name start
	pend   int   // current param name end
	vstart int   // current value start
	vend   int   // current value end
}

// internal parse from states
const (
	fbInit      uint8 = iota
	fbNameOrURI       /* 1st token, possible URI if no other token
	   and not <> present */
	fbNameOrURIEnd // 1st token end
	fbName
	fbQuoted
	fbURI
	fbURIFound
	fbNewPossibleParam
	fbPossibleParamName // possible param start (first non WS char)
	fbPossibleParamNameEnd
	fbNewParam     // new param found (';')
	fbParamName    // param name (first non WS param char)
	fbParamNameEnd // space seen after name => complete token
	fbNewParamVal  // new param value found
	fbParamVal     // 1st non-WS value char found
	fbParamValEnd  // space seen after val => complete token
	fbNewPossibleVal
	fbPossibleVal
	fbPossibleValEnd
	fbQuotedVal
	fbQuotedPossibleVal
	fbTagT
	fbTagA
	fbTagG
	fbTagEq
	fbTagVal
	fbPTagT // possible Tag*
	fbPTagA
	fbPTagG
	fbPTagEq
	fbPTagVal
	fbFIN // parsing ended
)

// ParseFromVal parses the value/content of a From or To header.
// The parameters are: a message buffer, the offset in the buffer where the
// from: (or to:) value starts (should point after the ':') and a pointer
// to a from value structure that will be filled.
// It returns a new offset, pointing immediately after the end of the header
// (it could point to len(buf) if the header end the end of the buffer
// coincide) and an error. If the header is not fully contained in buf[offs:]
//  ErrHdrMoreBytes will be returned and this function can be called again
// when more bytes are available, with the same buffer, the returned
// offset ("continue point") and the same pfrom structure.
// WARNING: for now Name and Params might contain extra trailing whitespace
//          (no attempt is made to eliminate it). URI and Tag are
//           auto-trimmed.
func ParseFromVal(buf []byte, offs int, pfrom *PFromBody) (int, ErrorHdr) {
	// Name-addr <addr>;params
	// internal parser state

	if pfrom.state == fbFIN {
		// called again after finishing
		return offs, 0 // or report error?
	}
	var s int = pfrom.soffs // saved "component" start offset
	i := offs
	var n, crl int // next non lws and crlf length
	var err ErrorHdr
	for i < len(buf) {
		c := buf[i]
		switch pfrom.state {
		case fbInit, fbName, fbNameOrURI, fbNameOrURIEnd:
			// a from header might consist only of a URI
			// (e.g. From: sip:foo@bar.com;tag=x). In this case
			// any uri parameters are in fact header parameters
			switch c {
			case ' ', '\t', '\n', '\r':
				// if LWS found and not fbInit => token end
				if pfrom.state == fbNameOrURI {
					// possible uri
					pfrom.URI.Set(s, i)
					pfrom.V.Extend(i)
					pfrom.state = fbNameOrURIEnd
				}
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
			case '<':
				if pfrom.state != fbInit {
					pfrom.Name.Set(s, i)
					// if in fbNameOrURIEnd -> 1st token is for sure no uri
					pfrom.URI.Reset()
					pfrom.Params.Reset()
					pfrom.Tag.Reset()
				} else { // fbInit
					pfrom.V.Set(i, i) // start of value
				}
				s = i + 1
				pfrom.state = fbURI
			case '"':
				if pfrom.state == fbInit {
					s = i
					pfrom.V.Set(i, i)
				} else {
					// if in fbNameOrURIEnd -> 1st token is for sure no uri
					pfrom.URI.Reset()
					pfrom.Params.Reset()
					pfrom.Tag.Reset()
				}
				pfrom.state = fbQuoted
			case ';': // look for ';' in fbNameOrUri -> possible param
				if pfrom.state == fbNameOrURI {
					pfrom.URI.Set(s, i) // possible uri
					pfrom.V.Extend(i + 1)
					s = i + 1
					pfrom.state = fbNewPossibleParam
				} else if pfrom.state == fbNameOrURIEnd {
					// e.g.:  sip:foo ;tag=1234
					pfrom.state = fbNewPossibleParam
				} else { // fbInit or fbName -> invalid char
					return i, ErrHdrBadChar
				}
			case '>':
				return i, ErrHdrBadChar
			default:
				if pfrom.state == fbInit {
					s = i
					pfrom.V.Set(i, i)
					pfrom.state = fbNameOrURI // 1st token might be the uri
				} else if pfrom.state == fbNameOrURIEnd {
					// more chars after 1st token => 1st token cannot be a uri
					pfrom.state = fbName
					pfrom.URI.Reset()
					pfrom.Params.Reset()
					pfrom.Tag.Reset()
				} // else keep current state
			}
		case fbQuoted, fbQuotedVal, fbQuotedPossibleVal:
			switch c {
			case '"':
				if pfrom.state == fbQuoted {
					pfrom.state = fbName
				} else if pfrom.state == fbQuotedVal {
					pfrom.state = fbParamVal
				} else { // fbQuotedPossibleVal
					pfrom.state = fbPossibleVal
				}
			case '\\': // quoted-pair
				if (i + 1) < len(buf) {
					if buf[i+1] == '\r' || buf[i+1] == '\n' {
						// CR or LF not allowed in escape pairs
						return i + 1, ErrHdrBadChar
					}
					i += 2 // skip '\x'
					continue
				}
				goto moreBytes
			case ' ', '\t', '\n', '\r':
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
		case fbURI:
			switch c {
			case '>':
				pfrom.URI.Set(s, i)
				pfrom.V.Extend(i + 1)
				pfrom.state = fbURIFound
			case '<', ' ', '\t', '\n', '\r': // not allowed inside <>
				return i, ErrHdrBadChar
			}
		case fbURIFound:
			switch c {
			case ' ', '\t', '\n', '\r':
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
			case ';':
				pfrom.state = fbNewParam
				s = 0 // start of actual params not yet known
			}
		case fbNewParam, fbNewPossibleParam, fbParamName, fbPossibleParamName:
			switch c {
			case ' ', '\t', '\n', '\r':
				n, crl, err = skipLWS(buf, i)
				if err == ErrHdrMoreBytes {
					if pfrom.state == fbParamName ||
						pfrom.state == fbPossibleParamName {
						// keep state and keep the offset to point
						// before the whitespace.
						// This allows properly checking for spaces
						// in a param name (ilegal multi-token pname)
						// after re-covering from HdrMoreBytes.
						goto moreBytes
					}
					// normal case, next offset after current whitespace
					i = n
					goto moreBytes
				}
				// advance state after skipping WS
				if pfrom.state == fbParamName {
					pfrom.state = fbParamNameEnd
					pfrom.pend = i
				} else if pfrom.state == fbPossibleParamName {
					pfrom.state = fbPossibleParamNameEnd
					pfrom.pend = i
				}

				if err == 0 {
					i = n
					continue
				}
				if err == ErrHdrEOH {
					// end of header
					goto endOfHdr
				}
				return n, err
			case '=':
				if pfrom.state == fbParamName {
					pfrom.state = fbNewParamVal
					pfrom.pend = i
				} else if pfrom.state == fbPossibleParamName {
					pfrom.state = fbNewPossibleVal
					pfrom.pend = i
				} else {
					// not allowed: ";="
					return i, ErrHdrBadChar
				}
			case '<':
				/* even in possible param, we already encountered a ';' =>
				   not allowed ( sip:foo;v<sip:realuri> not allowed) */
				fallthrough
			case '>':
				return i, ErrHdrBadChar
			case ';': // new param
				// fbNew* :llow empty params. eg.: foo.bar;;p2
				// else something like p1;p2...
				if pfrom.state == fbParamName {
					pfrom.state = fbNewParam
					pfrom.pend = i
				} else if pfrom.state == fbPossibleParamName {
					pfrom.state = fbNewPossibleParam
					pfrom.pend = i
				}
			default:
				if pfrom.state == fbNewParam {
					pfrom.state = fbParamName
					pfrom.pstart = i
				} else if pfrom.state == fbNewPossibleParam {
					pfrom.state = fbPossibleParamName
					pfrom.pstart = i
				}
				if pfrom.Params.Offs == 0 {
					// first non-space char after ';'
					pfrom.Params.Offs = OffsT(i) // start of params
				}
			}
		case fbParamNameEnd, fbPossibleParamNameEnd:
			switch c {
			case '=':
				if pfrom.state == fbParamNameEnd {
					pfrom.state = fbNewParamVal
					pfrom.vstart = i + 1 // in case we have an empty value
				} else {
					pfrom.state = fbNewPossibleVal
					pfrom.vstart = i + 1 // in case we have an empty value
				}
			case ';':
				if pfrom.state == fbParamNameEnd {
					pfrom.state = fbNewParam
				} else {
					pfrom.state = fbNewPossibleParam
				}
			default:
				// no other char allowed after a param name token
				// (the whitespace was already skipped in fb*ParamName)
				return i, ErrHdrBadChar

			}
		case fbNewParamVal, fbNewPossibleVal, fbParamVal, fbPossibleVal:
			switch c {
			case ' ', '\t', '\n', '\r':
				n, crl, err = skipLWS(buf, i)
				if err == ErrHdrMoreBytes {
					if pfrom.state == fbParamVal ||
						pfrom.state == fbPossibleVal {
						// keep state and keep the offset to point
						// before the whitespace.
						// This allows properly checking for spaces
						// in a value (ilegal multi-token values)
						// after re-covering from HdrMoreBytes.
						goto moreBytes
					}
					// normal case, next offset after current whitespace
					i = n
					goto moreBytes
				}
				// advance state after skipping WS
				if pfrom.state == fbParamVal {
					pfrom.state = fbParamValEnd
					pfrom.vend = i
				} else if pfrom.state == fbPossibleVal {
					pfrom.state = fbPossibleValEnd
					pfrom.vend = i
				}

				if err == 0 {
					i = n
					continue
				}
				if err == ErrHdrEOH {
					// end of header
					goto endOfHdr
				}
				return n, err
			case ';':
				if pfrom.state == fbNewParamVal || pfrom.state == fbParamVal {
					pfrom.state = fbNewParam
					pfrom.vend = i
					setFromParamVal(buf, pfrom)
				} else {
					pfrom.state = fbNewPossibleParam
					pfrom.vend = i
					setFromParamVal(buf, pfrom)
				}
			case '=', '<', '>':
				return i, ErrHdrBadChar
			case '"':
				if pfrom.state == fbParamVal {
					pfrom.state = fbQuotedVal
				} else if pfrom.state == fbNewParamVal {
					pfrom.state = fbQuotedVal
					pfrom.vstart = i
				} else if pfrom.state == fbPossibleVal {
					pfrom.state = fbQuotedPossibleVal
				} else { // fbNewPossibleVal
					pfrom.state = fbQuotedPossibleVal
					pfrom.vstart = i
				}
			default:
				if pfrom.state == fbNewParamVal {
					pfrom.state = fbParamVal
					pfrom.vstart = i
				} else if pfrom.state == fbNewPossibleVal {
					pfrom.state = fbPossibleVal
					pfrom.vstart = i
				}
			}
		case fbParamValEnd, fbPossibleValEnd:
			switch c {
			case ';':
				if pfrom.state == fbParamValEnd {
					pfrom.state = fbNewParam
					setFromParamVal(buf, pfrom)
				} else {
					pfrom.state = fbNewPossibleParam
					setFromParamVal(buf, pfrom)
				}
			default:
				// no other char allowed after a param value token
				return i, ErrHdrBadChar
			}
		}
		i++
	}
moreBytes:
	// end of buffer
	pfrom.soffs = s
	return i, ErrHdrMoreBytes
endOfHdr:
	// here i will point to first WS char (including CR & LF)
	//      n will point to the line end (CR or LF)
	//      crl will contain the line end length (1 or 2) so that
	//      n+crl is the first char in the new header
	switch pfrom.state {
	case fbURIFound, fbNameOrURIEnd:
		// do nothing
	case fbNameOrURI:
		// 1 token => it's the uri (e.g. sip:foo@bar)
		pfrom.URI.Set(s, i)
		pfrom.V.Extend(i)
	case fbNewParam, fbParamNameEnd, fbNewPossibleParam, fbPossibleParamNameEnd:
		// uri or possible uri already found, make sure the params end is set
		//pfrom.Params.Set(int(pfrom.Params.Offs), i)
		pfrom.Params.Extend(i)
		pfrom.V.Extend(i)
	case fbParamValEnd, fbPossibleValEnd:
		setFromParamVal(buf, pfrom)
		//pfrom.Params.Set(int(pfrom.Params.Offs), i)
		pfrom.Params.Extend(i)
		pfrom.V.Extend(i)
	case fbParamVal, fbPossibleVal:
		fallthrough
	case fbNewParamVal, fbNewPossibleVal: // empty param val e.g. p=
		pfrom.vend = i
		setFromParamVal(buf, pfrom)
		// uri or possible uri already found, make sure the params end is set
		//pfrom.Params.Set(int(pfrom.Params.Offs), i)
		pfrom.Params.Extend(i)
		pfrom.V.Extend(i)
	case fbInit, fbName, fbURI, fbQuoted, fbQuotedVal, fbQuotedPossibleVal:
		// end of header in unexpected state => bad header
		return n + crl, ErrHdrBad
	default:
		return n + crl, ErrHdrBug
	}
	pfrom.state = fbFIN
	pfrom.soffs = 0
	return n + crl, 0
}

func setFromParamVal(buf []byte, pf *PFromBody) int {
	tag := [...]byte{'t', 'a', 'g'}
	if (pf.pstart < pf.pend) && (pf.vstart < pf.vend) {
		// for now only tag=val is recognized, hard-wired
		if ((pf.pend - pf.pstart) == len(tag)) &&
			bytescase.CmpEq(buf[pf.pstart:pf.pend], tag[:]) {
			pf.Tag.Set(pf.vstart, pf.vend)
		}
		pf.pstart = 0
		pf.pend = 0
		pf.vstart = 0
		pf.vend = 0
		return 0
	}
	pf.pstart = 0
	pf.pend = 0
	pf.vstart = 0
	pf.vend = 0
	return -1
}
