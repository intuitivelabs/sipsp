package sipsp

import ()

type PSIPMsg struct {
	FL   PFLine   // first line request/response
	PV   PHdrVals // parsed (selected )header values
	HL   HdrLst   // headers
	Body PField   // message body

	hdrs         [10]Hdr       // headers broken into name: val used inside HL
	contacts     [10]PFromBody // default parsed contacts space
	Buf          []byte        // message data, parsed values will point inside it
	SIPMsgIState               // internal state
}

func (m *PSIPMsg) Reset() {
	*m = PSIPMsg{}
	m.FL.Reset()
	m.PV.Reset()
	m.HL.Reset()
	m.Body.Reset()
	m.SIPMsgIState = SIPMsgIState{}
}

func (m *PSIPMsg) Init(msg []byte, hdrs []Hdr, contacts []PFromBody) {
	m.Reset()
	m.Buf = msg
	if hdrs != nil {
		m.HL.Hdrs = hdrs
	} else {
		m.HL.Hdrs = m.hdrs[:]
	}
	if contacts != nil {
		m.PV.Contacts.Init(contacts)
	} else {
		m.PV.Contacts.Init(m.contacts[:])
	}
}

func (m *PSIPMsg) Parsed() bool {
	return m.state == SIPMsgFIN
}

func (m *PSIPMsg) Err() bool {
	return m.state == SIPMsgErr
}

func (m *PSIPMsg) Request() bool {
	return m.FL.Request()
}

func (m *PSIPMsg) Method() SIPMethod {

	if m.Request() {
		return m.FL.MethodNo
	}
	return m.PV.CSeq.MethodNo
}

type SIPMsgIState struct {
	state uint8
	offs  int
}

const (
	SIPMsgInit uint8 = iota
	SIPMsgFLine
	SIPMsgHeaders
	SIPMsgBody
	SIPMsgErr
	SIPMsgNoCLen // no Content-Length and Content-Length required
	SIPMsgFIN    // fully parsed
)

// parsing flags
const (
	SIPMsgSkipBodyF   = 1 << iota // don't parse the body (return offset = body start)
	SIPMsgCLenReqF                // error if SIPMsgSkipBodyF and no CLen
	SIPMsgNoMoreDataF             // no more message data, stop at end of buf
)

func ParseSIPMsg(buf []byte, offs int, msg *PSIPMsg, flags uint8) (int, ErrorHdr) {

	var o int = offs
	var err ErrorHdr
	switch msg.state {
	case SIPMsgInit:
		msg.offs = offs
		msg.state = SIPMsgFLine
		fallthrough
	case SIPMsgFLine:
		if o, err = ParseFLine(buf, o, &msg.FL); err != 0 {
			goto errFL
		}
		msg.state = SIPMsgHeaders
		fallthrough
	case SIPMsgHeaders:
		if o, err = ParseHeaders(buf, o, &msg.HL, &msg.PV); err != 0 {
			goto errHL
		}
		msg.state = SIPMsgBody
		fallthrough
	case SIPMsgBody:
		msg.Body.Set(o, o)
		if (flags & SIPMsgSkipBodyF) != 0 {
			if flags&SIPMsgCLenReqF != 0 && !msg.PV.CLen.Parsed() {
				msg.state = SIPMsgNoCLen
				msg.Buf = buf[msg.offs:o]
				return o, ErrHdrNoCLen
			}
			msg.state = SIPMsgFIN
			goto end
		}
		if msg.PV.CLen.Parsed() {
			// skip  msg.PV.CLen.Len bytes
			if (o + int(msg.PV.CLen.Len)) > len(buf) {
				o = len(buf)
				if (flags & SIPMsgNoMoreDataF) != 0 {
					// allow truncated body
					goto end
				}
				return o, ErrHdrMoreBytes
			}
			o += int(msg.PV.CLen.Len)
		} else {
			if (flags & SIPMsgCLenReqF) != 0 {
				// no CLen, assume it's 0
				goto end
			}
			// no clen, use whole buffer
			o = len(buf)
		}
	default:
		err = ErrHdrBug
		goto errBUG
	}
end:
	msg.Body.Extend(o)
	msg.Buf = buf[msg.offs:o]
	msg.state = SIPMsgFIN
	return o, 0
errFL:
errHL:
errBUG:
	if err != ErrHdrMoreBytes {
		msg.state = SIPMsgErr
	} else if (flags & SIPMsgNoMoreDataF) != 0 {
		msg.state = SIPMsgErr
		err = ErrHdrTrunc
	}
	return o, err
}
