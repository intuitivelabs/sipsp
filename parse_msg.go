// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipsp

import ()

// PSIPMsg contains a fully or partially parsed SIP message.
// If the message is not fully contained in the passed input, the internal
// parsing state will be saved internally and parsing can be resumed later
// when more input is available.
type PSIPMsg struct {
	FL   PFLine   // first line request/response
	PV   PHdrVals // parsed (selected )header values
	HL   HdrLst   // headers
	Body PField   // message body

	hdrs     [10]Hdr       // headers broken into name: val used inside HL
	contacts [10]PFromBody // default parsed contacts space
	// Parsed data slice (copy of the original slice passed as parameter to
	// the ParseSIPMsg() function). Parsed values will point inside it.
	// Note however that the actual message starts at Buf[intial_used_offset],
	// which might be different from Buf[0].
	Buf          []byte
	RawMsg       []byte // raw message data (actual raw message from RawMsg[0])
	SIPMsgIState        // internal state
}

// Reset re-initializes the parsed message and the internal parsing state.
func (m *PSIPMsg) Reset() {
	*m = PSIPMsg{}
	m.FL.Reset()
	m.PV.Reset()
	m.HL.Reset()
	m.Body.Reset()
	m.SIPMsgIState = SIPMsgIState{}
}

// Init initializes a PSIPMsg with a new message and empty arrays for
// holding the parsed headers and contacts values.
// If some place holder arrays are nil, default 10-elements private arrays
// will be used instead (PSIPMsg.hdrs or PSIPMsg.contacts).
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

// Parsed returns true if the message if fully parsed
// (and no more input is needed).
func (m *PSIPMsg) Parsed() bool {
	return m.state == SIPMsgFIN
}

// Err returns true if parsing failed.
func (m *PSIPMsg) Err() bool {
	return m.state == SIPMsgErr
}

// Request returns true if the message is a SIP request.
func (m *PSIPMsg) Request() bool {
	return m.FL.Request()
}

// Method returns the numeric SIP method.
// If the message is a reply, the method from the CSeq header will be used.
func (m *PSIPMsg) Method() SIPMethod {

	if m.Request() {
		return m.FL.MethodNo
	}
	return m.PV.CSeq.MethodNo
}

// SIPMsgIState holds the internal parsing state.
type SIPMsgIState struct {
	state uint8
	offs  int
}

// Parsing states.
const (
	SIPMsgInit uint8 = iota
	SIPMsgFLine
	SIPMsgHeaders
	SIPMsgBody
	SIPMsgErr
	SIPMsgNoCLen // no Content-Length and Content-Length required
	SIPMsgFIN    // fully parsed
)

// Parsing flags for ParseSIPMsg().
const (
	SIPMsgSkipBodyF   = 1 << iota // don't parse the body (return offset = body start)
	SIPMsgCLenReqF                // error if SIPMsgSkipBodyF and no CLen
	SIPMsgNoMoreDataF             // no more message data, stop at end of buf
)

// ParseSIPMsg parses a SIP message contained in buf[], starting
// at offset offs. If the parsing requires more data (ErrHdrMoreBytes),
// this function should be called again with an extended buf containing the
// old data + new data and with offs equal to the last returned value (so
// that parsing will continue from that point).
// The offset in the initial call should be 0, but it can have different
// values.
// It returns the offset at which parsing finished and an error.
// If no more input data is available (buf contains everything, e.g. a full UDP
// received packet) pass the SIPMsgNoMoreDataF flag.
// Note that a reference to buf[] will be "saved" inside msg.Buf when
// parsing is complete.
func ParseSIPMsg(buf []byte, offs int, msg *PSIPMsg, flags uint8) (int, ErrorHdr) {

	var o = offs
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
				msg.Buf = buf[0:o]
				msg.RawMsg = msg.Buf[msg.offs:o]
				return o, ErrHdrNoCLen
			}
			msg.state = SIPMsgFIN
			goto end
		}
		if msg.PV.CLen.Parsed() {
			// skip  msg.PV.CLen.Len bytes
			if (o + int(msg.PV.CLen.UIVal)) > len(buf) {
				o = len(buf)
				if (flags & SIPMsgNoMoreDataF) != 0 {
					// allow truncated body
					goto end
				}
				return o, ErrHdrMoreBytes
			}
			o += int(msg.PV.CLen.UIVal)
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
	msg.Buf = buf[0:o]
	msg.RawMsg = msg.Buf[msg.offs:o]
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
