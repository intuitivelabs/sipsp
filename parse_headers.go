package sipsp

import (
	"andrei/sipsp/bytescase"
)

type HdrT uint16

type HdrFlags uint16

func (f *HdrFlags) Reset() {
	*f = 0
}

func (f *HdrFlags) Set(Type HdrT) {
	*f |= 1 << Type
}

func (f *HdrFlags) Clear(Type HdrT) {
	*f &^= 1 << Type // equiv to & ^(...)
}

func (f HdrFlags) Test(Type HdrT) bool {
	return (f & (1 << Type)) != 0
}

func (f HdrFlags) Any(types ...HdrT) bool {
	for _, t := range types {
		if f&(1<<t) != 0 {
			return true
		}
	}
	return false
}

func (f HdrFlags) AllSet(types ...HdrT) bool {
	for _, t := range types {
		if f&(1<<t) == 0 {
			return false
		}
	}
	return true
}

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
// The header name should not contain any leading or ending whitespace.
func GetHdrType(name []byte) HdrT {
	i := hashHdrName(name)
	for _, h := range hdrNameLookup[i] {
		if bytescase.CmpEq(name, h.n) {
			return h.t
		}
	}
	return HdrOther
}

type Hdr struct {
	Type HdrT
	Name PField
	Val  PField
	HdrIState
}

func (h *Hdr) Reset() {
	*h = Hdr{}
}

func (h *Hdr) Missing() bool {
	return h.Type == HdrNone
}

type HdrIState struct {
	state uint8
}

type HdrLst struct {
	PFlags HdrFlags // parsed headers as flags
	N      int      // total numbers of headers found (can be > len(Hdrs))
	Hdrs   []Hdr
	h      [int(HdrOther) - 1]Hdr // list of type -> hdr
	HdrLstIState
}

type HdrLstIState struct {
	hdr Hdr // tmp. header used for saving the state
}

func (hl *HdrLst) Reset() {
	hdrs := hl.Hdrs
	*hl = HdrLst{}
	for i := 0; i < len(hdrs); i++ {
		hdrs[i].Reset()
	}
	hl.Hdrs = hdrs
}

func (hl *HdrLst) GetHdr(t HdrT) *Hdr {
	if t > HdrNone && t < HdrOther {
		return &hl.h[int(t)-1] // no value for HdrNone or HdrOther
	}
	return nil
}

func (hl *HdrLst) SetHdr(newhdr *Hdr) bool {
	i := int(newhdr.Type) - 1
	if i >= 0 && i < len(hl.h) && hl.h[i].Missing() {
		hl.h[i] = *newhdr
		return true
	}
	return false
}

// PHBodies defines an interface for getting pointer to parsed bodies structs.
type PHBodies interface {
	GetFrom() *PFromBody
	GetTo() *PFromBody
	GetCallID() *PCallIDBody
	GetCSeq() *PCSeqBody
	GetCLen() *PUIntBody
	GetContacts() *PContacts
	Reset()
}

// PHdrVals holds all the header specific parsed values structures.
// (implement PHBodies=
type PHdrVals struct {
	From     PFromBody
	To       PFromBody
	Callid   PCallIDBody
	CSeq     PCSeqBody
	CLen     PUIntBody
	Contacts PContacts
}

func (hv *PHdrVals) Reset() {
	hv.From.Reset()
	hv.To.Reset()
	hv.Callid.Reset()
	hv.CSeq.Reset()
	hv.CLen.Reset()
	hv.Contacts.Reset()
}

func (hv *PHdrVals) Init(contactsbuf []PFromBody) {
	hv.Reset()
	hv.Contacts.Init(contactsbuf)
}

func (hv *PHdrVals) GetFrom() *PFromBody {
	return &hv.From
}

func (hv *PHdrVals) GetTo() *PFromBody {
	return &hv.To
}

func (hv *PHdrVals) GetCSeq() *PCSeqBody {
	return &hv.CSeq
}

func (hv *PHdrVals) GetCallID() *PCallIDBody {
	return &hv.Callid
}

func (hv *PHdrVals) GetCLen() *PCLenBody {
	return &hv.CLen
}

func (hv *PHdrVals) GetContacts() *PContacts {
	return &hv.Contacts
}

// ParseHdrLine parses a header from a SIP message.
// The parameters are: a message buffer, the offset in the buffer where the
// message starts, a pointer to a Hdr structure that will be filled
// and a PHBodies interface (defining methods to obtain pointers to
//  from, to, callid, cseq and content-length specific parsed body structures
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
				h.Val = clenb.CLen
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
// It returns offset after parsed headers and no error (0) on success.
// Special error values: ErrHdrMoreBytes - more data needed, call again
//                       with returned offset and same headers struct.
//                       ErrHdrEmpty - no headers (empty line found first)
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
