// // Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
// //
// // Use of this source code is governed by source-available license
// // that can be found in the LICENSE file in the root of the source
// // tree.

package sipsp

import (
	"github.com/intuitivelabs/bytescase"
)

// PFLine contains the parsed first line of a SIP message (request or reply).
type PFLine struct {
	Status     uint16 // reply status code, 0 for requests
	MethodNo   SIPMethod
	Method     PField // request method, empty in replies
	URI        PField // request URI
	Version    PField // sip version (e..g SIP/2.0), common
	StatusCode PField // reply status as string (empty for requests)
	Reason     PField // reply reason
	PFLineIState
}

func (fl *PFLine) Reset() {
	*fl = PFLine{}
}

func (fl *PFLine) Request() bool {
	return fl.Status == 0
}

func (fl *PFLine) Empty() bool {
	return fl.state == flInit
}

func (fl *PFLine) Parsed() bool {
	return fl.state == flFIN
}

func (fl *PFLine) Pending() bool {
	return fl.state != flFIN && fl.state != flInit
}

type PFLineIState struct {
	state uint8 // internal parser state
}

// internal parser state
const (
	flInit uint8 = iota
	flReqMethod
	flReqURI
	flReqVer
	flRplStatus
	flRplReason
	flCRLF
	flFIN
)

// constant arrays
var sipVer = []byte("SIP/2.0")    // sip version
var sipVerSP = []byte("SIP/2.0 ") // sip version including space

// ParseFLine parses the request/response line (first line) of a SIP message.
// The parameters are: a message buffer, the offset in the buffer where the
// message starts and a pointer to a PFLine structure that will be filled.
// It returns a new offset, pointing immediately after the end of the first
// line (it could point to len(buf) if the header and the end of the buffer
// coincide) and an error. If the first line  is not fully contained in
// buf[offs:] ErrHdrMoreBytes will be returned and this function can be called
// again when more bytes are available, with the same buffer, the returned
// offset ("continue point") and the same PFLine structure.
func ParseFLine(buf []byte, offs int, pl *PFLine) (int, ErrorHdr) {

	// grammar:
	//	request: method SP   uri   SP version CRLF
	//	reply:   version SP status SP reason  CRLF
	// where SP == single space
	i := offs
	switch pl.state {
	case flInit:
		if (len(buf) - i) < (len(sipVerSP) + 3 /*SP+CRLF*/ + 3 /* status */) {
			// message too small
			goto moreBytes
		}
		if l, match := bytescase.Prefix(sipVerSP, buf[i:]); match {
			// matched sip_version SP   => is a reply, l points _after_ space
			pl.Version.Set(i, i+l-1)
			pl.state = flRplStatus
			i += l
			// no need to check again for length, initial length check includes
			// space for status code
			if buf[i+3] != ' ' ||
				!((buf[i] >= '0' && buf[i] <= '9') &&
					(buf[i+1] >= '0' && buf[i+1] <= '9') &&
					(buf[i+2] >= '0' && buf[i+2] <= '9')) {
				// non numerical, too big or too small status
				return i, ErrHdrBadChar
			}
			pl.StatusCode.Set(i, i+3)
			pl.Status =
				uint16(buf[i]-'0')*100 + uint16(buf[i+1]-'0')*10 +
					uint16(buf[i+2]-'0')
			i += 4 // skip over status + space
			pl.Reason.Set(i, i)
			pl.state = flRplReason
			var err ErrorHdr
			var crl int
			if i, crl, err = skipLine(buf, i); err != 0 {
				return i, err // could be moreBytes
			}
			pl.Reason.Extend(i - crl)
			goto endOk
		}
		// request => skip over the 1st token
		pl.state = flReqMethod
		pl.Method.Set(i, i)
		fallthrough
	case flReqMethod:
		i = skipToken(buf, i)
		if i >= len(buf) {
			goto moreBytes
		}
		if buf[i] != ' ' { // '\t' , CR or LF => error
			return i, ErrHdrBadChar
		}
		pl.Method.Extend(i)
		if pl.Method.Empty() {
			goto errEmptyTok
		}
		pl.MethodNo = GetMethodNo(pl.Method.Get(buf))
		i++
		pl.state = flReqURI
		pl.URI.Set(i, i)
		fallthrough
	case flReqURI:
		i = skipToken(buf, i)
		if i >= len(buf) {
			goto moreBytes
		}
		if buf[i] != ' ' { // '\t' , CR or LF => error
			return i, ErrHdrBadChar
		}
		pl.URI.Extend(i)
		if pl.URI.Empty() {
			goto errEmptyTok
		}
		i++
		pl.state = flReqVer
		pl.Version.Set(i, i)
		fallthrough
	case flReqVer:
		i = skipToken(buf, i)
		if i >= len(buf) {
			goto moreBytes
		}
		if buf[i] != '\r' && buf[i] != '\n' { // ' ' or '\t' at the end => error
			return i, ErrHdrBadChar
		}
		pl.Version.Extend(i)
		if pl.Version.Empty() {
			goto errEmptyTok
		}
		pl.state = flCRLF
		fallthrough
	case flCRLF:
		var end int
		var err ErrorHdr
		if end, _, err = skipCRLF(buf, i); err != 0 {
			return end, err // could be moreBytes
		}
		i = end
		goto endOk
	case flRplReason:
		var err ErrorHdr
		var crl int
		if i, crl, err = skipLine(buf, i); err != 0 {
			return i, err // could be moreBytes
		}
		pl.Reason.Extend(i - crl)
	}
endOk:
	pl.state = flFIN
	return i, 0
moreBytes:
	return i, ErrHdrMoreBytes
errEmptyTok:
	return i, ErrHdrBadChar
}
