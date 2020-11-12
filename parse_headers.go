// // Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
// //
// // Use of this source code is governed by source-available license
// // that can be found in the LICENSE file in the root of the source
// // tree.

package sipsp

import (
	"github.com/intuitivelabs/bytescase"
)

// HdrT is used to hold the header type as a numeric constant.
type HdrT uint16

// HdrFlags packs several header values into bit flags.
type HdrFlags uint16

// Reset initializes a HdrFlags.
func (f *HdrFlags) Reset() {
	*f = 0
}

// Set sets the header flag corresponding to the passed header type.
func (f *HdrFlags) Set(Type HdrT) {
	*f |= 1 << Type
}

// Clear resets the header flag corresponding to the passed header type.
func (f *HdrFlags) Clear(Type HdrT) {
	*f &^= 1 << Type // equiv to & ^(...)
}

// Test returns true if the flag corresponding to the passed header type
// is set.
func (f HdrFlags) Test(Type HdrT) bool {
	return (f & (1 << Type)) != 0
}

// Any returns true if at least one of the passed header types is set.
func (f HdrFlags) Any(types ...HdrT) bool {
	for _, t := range types {
		if f&(1<<t) != 0 {
			return true
		}
	}
	return false
}

// AllSet returns true if all of the passed header types are set.
func (f HdrFlags) AllSet(types ...HdrT) bool {
	for _, t := range types {
		if f&(1<<t) == 0 {
			return false
		}
	}
	return true
}

// HdrT header types constants.
const (
	HdrNone HdrT = iota
	HdrFrom
	HdrTo
	HdrCallID
	HdrCSeq
	HdrCLen
	HdrContact
	HdrExpires
	HdrUA
	HdrRecordRoute
	HdrRoute
	HdrOther // generic, non recognized header
)

// HdrFlags constants for each header type.
const (
	HdrFromF        HdrFlags = 1 << HdrFrom
	HdrToF          HdrFlags = 1 << HdrTo
	HdrCallIDF      HdrFlags = 1 << HdrCallID
	HdrCSeqF        HdrFlags = 1 << HdrCSeq
	HdrCLenF        HdrFlags = 1 << HdrCLen
	HdrContactF     HdrFlags = 1 << HdrContact
	HdrExpiresF     HdrFlags = 1 << HdrExpires
	HdrUAF          HdrFlags = 1 << HdrUA
	HdrRecordRouteF HdrFlags = 1 << HdrRecordRoute
	HdrRouteF       HdrFlags = 1 << HdrRoute
	HdrOtherF       HdrFlags = 1 << HdrOther
)

// pretty names for debugging and error reporting
var hdrTStr = [...]string{
	HdrNone:        "nil",
	HdrFrom:        "From",
	HdrTo:          "To",
	HdrCallID:      "Call-ID",
	HdrCSeq:        "Cseq",
	HdrCLen:        "Content-Length",
	HdrContact:     "Contact",
	HdrExpires:     "Expires",
	HdrUA:          "User-Agent",
	HdrRecordRoute: "Record-Router",
	HdrRoute:       "Route",
	HdrOther:       "Generic",
}

// String implements the Stringer interface.
func (t HdrT) String() string {
	if int(t) >= len(hdrTStr) || int(t) < 0 {
		return "invalid"
	}
	return hdrTStr[t]
}

// associates header name (as byte slice) to HdrT header type
type hdr2Type struct {
	n []byte
	t HdrT
}

// list of header-name <-> header type correspondence
// (always use lowercase)
var hdrName2Type = [...]hdr2Type{
	{n: []byte("from"), t: HdrFrom},
	{n: []byte("f"), t: HdrFrom},
	{n: []byte("to"), t: HdrTo},
	{n: []byte("t"), t: HdrTo},
	{n: []byte("call-id"), t: HdrCallID},
	{n: []byte("i"), t: HdrCallID},
	{n: []byte("cseq"), t: HdrCSeq},
	{n: []byte("content-length"), t: HdrCLen},
	{n: []byte("l"), t: HdrCLen},
	{n: []byte("contact"), t: HdrContact},
	{n: []byte("m"), t: HdrContact},
	{n: []byte("expires"), t: HdrExpires},
	{n: []byte("user-agent"), t: HdrUA},
	{n: []byte("record-route"), t: HdrRecordRoute},
	{n: []byte("route"), t: HdrRoute},
}

const (
	hnBitsLen   uint = 2 // after changing this re-run testing
	hnBitsFChar uint = 4
)

var hdrNameLookup [1 << (hnBitsLen + hnBitsFChar)][]hdr2Type

func hashHdrName(n []byte) int {
	// simple hash:
	//           1stchar & mC | (len &mL<< bitsFChar)
	const (
		mC = (1 << hnBitsFChar) - 1
		mL = (1 << hnBitsLen) - 1
	)
	/* contact & callid will have the same hash, using this method...*/
	return (int(bytescase.ByteToLower(n[0])) & mC) |
		((len(n) & mL) << hnBitsFChar)
}

func init() {
	// init lookup arrays
	for _, h := range hdrName2Type {
		i := hashHdrName(h.n)
		hdrNameLookup[i] = append(hdrNameLookup[i], h)
	}
}

// GetHdrType returns the corresponding HdrT type for a given header name.
// The header name should not contain any leading or ending white space.
func GetHdrType(name []byte) HdrT {
	i := hashHdrName(name)
	for _, h := range hdrNameLookup[i] {
		if bytescase.CmpEq(name, h.n) {
			return h.t
		}
	}
	return HdrOther
}

// Hdr contains a partial or fully parsed header.
type Hdr struct {
	Type HdrT
	Name PField
	Val  PField
	HdrIState
}

// Reset re-initializes the parsing state and the parsed values.
func (h *Hdr) Reset() {
	*h = Hdr{}
}

// Missing returns true if the header is empty (not parsed).
func (h *Hdr) Missing() bool {
	return h.Type == HdrNone
}

// HdrIState contains internal header parsing state.
type HdrIState struct {
	state uint8
}

// HdrLst groups a list of parsed headers.
type HdrLst struct {
	PFlags HdrFlags               // parsed headers as flags
	N      int                    // total numbers of headers found (can be > len(Hdrs))
	Hdrs   []Hdr                  // all parsed headers, that fit in the slice.
	h      [int(HdrOther) - 1]Hdr // list of type -> hdr, pointing to the
	// first hdr with the corresponding type.
	HdrLstIState
}

// HdrLstIState contains internal HdrLst parsing state.
type HdrLstIState struct {
	hdr Hdr // tmp. header used for saving the state
}

// Reset re-initializes the parsing state and values.
func (hl *HdrLst) Reset() {
	hdrs := hl.Hdrs
	*hl = HdrLst{}
	for i := 0; i < len(hdrs); i++ {
		hdrs[i].Reset()
	}
	hl.Hdrs = hdrs
}

// GetHdr returns the first parsed header of the requested type.
// If not corresponding header was parsed it returns nil.
func (hl *HdrLst) GetHdr(t HdrT) *Hdr {
	if t > HdrNone && t < HdrOther {
		return &hl.h[int(t)-1] // no value for HdrNone or HdrOther
	}
	return nil
}

// SetHdr adds a new header to the  internal "first" header list (see GetHdr)
// if not already present.
// It returns true if successful and false if a header of the same type was
// already added or the header type is invalid.
func (hl *HdrLst) SetHdr(newhdr *Hdr) bool {
	i := int(newhdr.Type) - 1
	if i >= 0 && i < len(hl.h) && hl.h[i].Missing() {
		hl.h[i] = *newhdr
		return true
	}
	return false
}

// PHBodies defines an interface for getting pointers to parsed bodies structs.
type PHBodies interface {
	GetFrom() *PFromBody
	GetTo() *PFromBody
	GetCallID() *PCallIDBody
	GetCSeq() *PCSeqBody
	GetCLen() *PUIntBody
	GetContacts() *PContacts
	GetExpires() *PUIntBody
	Reset()
}

// PHdrVals holds all the header specific parsed values structures.
// (implements PHBodies)
type PHdrVals struct {
	From     PFromBody
	To       PFromBody
	Callid   PCallIDBody
	CSeq     PCSeqBody
	CLen     PUIntBody
	Contacts PContacts
	Expires  PUIntBody
}

// Reset re-initializes all the parsed values.
func (hv *PHdrVals) Reset() {
	hv.From.Reset()
	hv.To.Reset()
	hv.Callid.Reset()
	hv.CSeq.Reset()
	hv.CLen.Reset()
	hv.Contacts.Reset()
	hv.Expires.Reset()
}

// Init initializes all the Contacts values to the passed contacsbuf
// and resets all the other values.
func (hv *PHdrVals) Init(contactsbuf []PFromBody) {
	hv.Reset()
	hv.Contacts.Init(contactsbuf)
}

// GetFrom returns a pointer to the parsed from.
// It implements the PHBodies interface.
func (hv *PHdrVals) GetFrom() *PFromBody {
	return &hv.From
}

// GetTo returns a pointer to the parsed to.
// It implements the PHBodies interface.
func (hv *PHdrVals) GetTo() *PFromBody {
	return &hv.To
}

// GetCSeq returns a pointer to the parsed cseq body.
// It implements the PHBodies interface.
func (hv *PHdrVals) GetCSeq() *PCSeqBody {
	return &hv.CSeq
}

// GetCallID returns a pointer to the parsed call-id body.
// It implements the PHBodies interface.
func (hv *PHdrVals) GetCallID() *PCallIDBody {
	return &hv.Callid
}

// GetCLen returns a pointer to the parsed content-length body.
// It implements the PHBodies interface.
func (hv *PHdrVals) GetCLen() *PUIntBody {
	return &hv.CLen
}

// GetContacts returns a pointer to the parsed contacts values.
// It implements the PHBodies interface.
func (hv *PHdrVals) GetContacts() *PContacts {
	return &hv.Contacts
}

// GetExpires returns a pointer to the parsed expire value.
// It implements the PHBodies interface.
func (hv *PHdrVals) GetExpires() *PUIntBody {
	return &hv.Expires
}

// MaxExpires returns the maximum expires time between all the contacts
// and a possible Expire header.
// If neither Contact: or Expire: header are present, it will return 0, false.
func (hv *PHdrVals) MaxExpires() (uint32, bool) {
	var max uint32
	var ok bool
	if hv.Contacts.Parsed() {
		max = hv.Contacts.MaxExpires
		ok = true
	}
	if hv.Expires.Parsed() {
		if max < hv.Expires.UIVal {
			max = hv.Expires.UIVal
		}
		ok = true
	}
	return max, ok
}

// ParseHdrLine parses a header from a SIP message.
// The parameters are: a message buffer, the offset in the buffer where the
// parsing should start (or continue), a pointer to a Hdr structure that will
// be filled and a PHBodies interface (defining methods to obtain pointers to
// from, to, callid, cseq and content-length specific parsed body structures
// that will be filled if one of the corresponding headers is found).
// It returns a new offset, pointing immediately after the end of the header
// (it could point to len(buf) if the header and the end of the buffer
// coincide) and an error. If the first line  is not fully contained in
// buf[offs:] ErrHdrMoreBytes will be returned and this function can be called
// again when more bytes are available, with the same buffer, the returned
// offset ("continue point") and the same Hdr structure.
// Another special error value is ErrHdrEmpty. It is returned if the header
// is empty ( CR LF). If previous headers were parsed, this means the end of
// headers was encountered. The offset returned is after the CRLF.
func ParseHdrLine(buf []byte, offs int, h *Hdr, hb PHBodies) (int, ErrorHdr) {
	// grammar:  Name SP* : LWS* val LWS* CRLF
	const (
		hInit uint8 = iota
		hName
		hNameEnd
		hBodyStart
		hVal
		hValEnd
		hFrom
		hTo
		hCallID
		hCSeq
		hCLen
		hContact
		hExpires
		hFIN
	)

	// helper internal function for parsing header specific values if
	//  header specific parser are available (else fall back to generic
	//  value parsing)
	parseBody := func(buf []byte, o int, h *Hdr, hb PHBodies) (int, ErrorHdr) {
		var err ErrorHdr
		n := o
		if hb != nil {
			switch h.Type {
			case HdrFrom:
				if fromb := hb.GetFrom(); fromb != nil && !fromb.Parsed() {
					h.state = hFrom
					n, err = ParseFromVal(buf, o, fromb)
					if err == 0 { /* fix hdr.Val */
						h.Val = fromb.V
					}
				}
			case HdrTo:
				if tob := hb.GetTo(); tob != nil && !tob.Parsed() {
					h.state = hTo
					n, err = ParseFromVal(buf, o, tob)
					if err == 0 { /* fix hdr.Val */
						h.Val = tob.V
					}
				}
			case HdrCallID:
				if callidb := hb.GetCallID(); callidb != nil && !callidb.Parsed() {
					h.state = hCallID
					n, err = ParseCallIDVal(buf, o, callidb)
					if err == 0 { /* fix hdr.Val */
						h.Val = callidb.CallID
					}
				}
			case HdrCSeq:
				if cseqb := hb.GetCSeq(); cseqb != nil && !cseqb.Parsed() {
					h.state = hCSeq
					n, err = ParseCSeqVal(buf, o, cseqb)
					if err == 0 { /* fix hdr.Val */
						h.Val = cseqb.V
					}
				}
			case HdrCLen:
				if clenb := hb.GetCLen(); clenb != nil && !clenb.Parsed() {
					h.state = hCLen
					n, err = ParseCLenVal(buf, o, clenb)
					if err == 0 { /* fix hdr.Val */
						h.Val = clenb.SVal
					}
				}
			case HdrContact:
				if contacts := hb.GetContacts(); contacts != nil {
					if h.state != hContact {
						// new contact header found
						contacts.HNo++
					}
					h.state = hContact
					n, err = ParseAllContactValues(buf, o, contacts)
					if err == 0 { /* fix hdr.Val */
						h.Val = contacts.LastHVal
					}
				}
			case HdrExpires:
				if expb := hb.GetExpires(); expb != nil && !expb.Parsed() {
					h.state = hExpires
					n, err = ParseExpiresVal(buf, o, expb)
					if err == 0 { /* fix hdr.Val */
						h.Val = expb.SVal
					}
				}
			}
		}
		return n, err
	}

	var crl int
	i := offs
	for i < len(buf) {
		switch h.state {
		case hInit:
			if (len(buf) - i) < 1 {
				goto moreBytes
			}
			if buf[i] == '\r' {
				if (len(buf) - i) < 2 {
					goto moreBytes
				}
				h.state = hFIN
				if buf[i+1] == '\n' {
					/* CRLF - end of header */
					return i + 2, ErrHdrEmpty
				}
				return i + 1, ErrHdrEmpty // single CR
			} else if buf[i] == '\n' {
				/* single LF, accept it as valid end of header */
				h.state = hFIN
				return i + 1, ErrHdrEmpty
			}
			h.state = hName
			h.Name.Set(i, i)
			fallthrough
		case hName:
			i = skipTokenDelim(buf, i, ':')
			if i >= len(buf) {
				goto moreBytes
			}
			if buf[i] == ' ' || buf[i] == '\t' {
				h.state = hNameEnd
				h.Name.Extend(i)
				if h.Name.Empty() {
					goto errEmptyTok
				}
				i++
			} else if buf[i] == ':' {
				h.state = hBodyStart
				h.Name.Extend(i)
				if h.Name.Empty() {
					goto errEmptyTok
				}
				h.Type = GetHdrType(h.Name.Get(buf))
				i++
				n, err := parseBody(buf, i, h, hb)
				if h.state != hBodyStart {
					if err == 0 {
						h.state = hFIN
					}
					return n, err
				}
			} else {
				// non WS after seeing a token => error
				goto errBadChar
			}
		case hNameEnd:
			i = skipWS(buf, i)
			if i >= len(buf) {
				goto moreBytes
			}
			if buf[i] == ':' {
				h.state = hBodyStart
				h.Type = GetHdrType(h.Name.Get(buf))
				i++
				n, err := parseBody(buf, i, h, hb)
				if h.state != hBodyStart {
					if err == 0 {
						h.state = hFIN
					}
					return n, err
				}
			} else {
				// non WS after seing a token => error
				goto errBadChar
			}
		case hBodyStart:
			var err ErrorHdr
			i, crl, err = skipLWS(buf, i)
			switch err {
			case 0:
				h.state = hVal
				h.Val.Set(i, i)
				crl = 0
			case ErrHdrEOH:
				// empty value
				goto endOfHdr
			case ErrHdrMoreBytes:
				fallthrough
			default:
				return i, err
			}
			i++
		case hVal:
			i = skipToken(buf, i)
			if i >= len(buf) {
				goto moreBytes
			}
			h.Val.Extend(i)
			h.state = hValEnd
			fallthrough
		case hValEnd:
			var err ErrorHdr
			i, crl, err = skipLWS(buf, i)
			switch err {
			case 0:
				h.state = hVal
				crl = 0
			case ErrHdrEOH:
				goto endOfHdr
			case ErrHdrMoreBytes:
				fallthrough
			default:
				return i, err
			}
			i++
		case hFrom: // continue from parsing
			fromb := hb.GetFrom()
			n, err := ParseFromVal(buf, i, fromb)
			if err == 0 { /* fix hdr.Val */
				h.Val = fromb.V
				h.state = hFIN
			}
			return n, err
		case hTo: // continue to parsing
			tob := hb.GetTo()
			n, err := ParseFromVal(buf, i, tob)
			if err == 0 { /* fix hdr.Val */
				h.Val = tob.V
				h.state = hFIN
			}
			return n, err
		case hCallID: // continue callid parsing
			callidb := hb.GetCallID()
			n, err := ParseCallIDVal(buf, i, callidb)
			if err == 0 { /* fix hdr.Val */
				h.Val = callidb.CallID
				h.state = hFIN
			}
			return n, err
		case hCSeq: // continue cseq parsing
			cseqb := hb.GetCSeq()
			n, err := ParseCSeqVal(buf, i, cseqb)
			if err == 0 { /* fix hdr.Val */
				h.Val = cseqb.V
				h.state = hFIN
			}
			return n, err
		case hCLen: // continue content-length parsing
			clenb := hb.GetCLen()
			n, err := ParseCLenVal(buf, i, clenb)
			if err == 0 { /* fix hdr.Val */
				h.Val = clenb.SVal
				h.state = hFIN
			}
			return n, err
		case hContact: // continue contact parsing
			contacts := hb.GetContacts()
			n, err := ParseAllContactValues(buf, i, contacts)
			if err == 0 { /* fix hdr.Val */
				h.Val = contacts.LastHVal
				h.state = hFIN
			}
			return n, err
		case hExpires: // continue expires parsing
			expb := hb.GetExpires()
			n, err := ParseExpiresVal(buf, i, expb)
			if err == 0 { /* fix hdr.Val */
				h.Val = expb.SVal
				h.state = hFIN
			}
			return n, err
		default: // unexpected state
			return i, ErrHdrBug
		}
	}
moreBytes:
	return i, ErrHdrMoreBytes
endOfHdr:
	h.state = hFIN
	return i + crl, 0
errBadChar:
errEmptyTok:
	return i, ErrHdrBadChar
}

// ParseHeaders parses all the headers till end of header marker (double CRLF).
// It returns an offset after parsed headers and no error (0) on success.
// Special error values: ErrHdrMoreBytes - more data needed, call again
//                       with returned offset and same headers struct.
//                       ErrHdrEmpty - no headers (empty line found first)
// See also ParseHdrLine().
func ParseHeaders(buf []byte, offs int, hl *HdrLst, hb PHBodies) (int, ErrorHdr) {

	i := offs
	for i < len(buf) {
		var h *Hdr
		if hl.N < len(hl.Hdrs) {
			h = &hl.Hdrs[hl.N]
		} else {
			h = &hl.hdr
		}
		n, err := ParseHdrLine(buf, i, h, hb)
		switch err {
		case 0:
			hl.PFlags.Set(h.Type)
			hl.SetHdr(h) // save "shortcut"
			if h == &hl.hdr {
				hl.hdr.Reset() // prepare it for reuse
			}
			i = n
			hl.N++
			continue
		case ErrHdrEmpty:
			if hl.N > 0 {
				// end of headers
				return n, 0
			}
			return n, err
		case ErrHdrMoreBytes:
			fallthrough
		default:
			return n, err
		}
	}
	return i, ErrHdrMoreBytes
}
