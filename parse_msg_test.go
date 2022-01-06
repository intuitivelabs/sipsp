// Copyright 2022 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipsp

import (
	"bytes"
	"math/rand"
	"testing"
)

// simple slow unescape \n, \r, \tm \\
// returns allocated byte slice
func unescapeCRLF(s string) []byte {
	buf := make([]byte, len(s)+2) // space for extra \r\n
	// handle escapes: \r & \n
	var i int
	var escape bool
	for _, b := range []byte(s) {
		if b == '\\' {
			escape = true
			continue
		} else {
			if escape {
				switch b {
				case 'n':
					buf[i] = '\n'
				case 'r':
					buf[i] = '\r'
				case 't':
					buf[i] = '\t'
				case '\\':
					buf[i] = '\\'
				default:
					// unrecognized => \char
					buf[i] = '\\'
					i++
					buf[i] = b
				}
				escape = false
			} else {
				buf[i] = b
			}
		}
		i++
	}
	buf = buf[:i]
	return buf
}

type msgTest struct {
	m    string   // message, w/o body
	body string   // message body
	pf   uint8    // parsing flags
	err  ErrorHdr // expected error
	n    int      // expected number of headers
	hf   HdrFlags // expected header flags
	offs int      // expected offset after parsing
}

var tests1 = [...]msgTest{
	{m: `INVITE sip:x@y.com SIP/2.0
From: <a@foo.bar>;tag=1234
To:<x@y.com>
Call-ID: a84b4c76e66710
CSeq: 314159 INVITE
Via: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bKnashds8
Max-Forwards: 70
Date: Thu, 21 Feb 2002 13:02:03 GMT
Content-Length: 141
`, n: 8,
		hf: HdrFromF | HdrToF | HdrCallIDF | HdrCSeqF | HdrOtherF |
			HdrCLenF,
		body: `v=0
o=UserA 2890844526 2890844526 IN IP4 here.com
s=Session SDP
c=IN IP4 pc33.atlanta.com
t=0 0
m=audio 49172 RTP/AVP 0
a=rtpmap:0 PCMU/8000
`, /* len= 141 (CR only + CR at the end) */
	},
	{m: `REGISTER sip:b@foo.bar SIP/2.0
From: <sip:b@foo.bar>;tag=1234\r
To:<sip:b@foo.bar>\r
Call-ID: a84b4c76e66710\r
CSeq: 314159 REGISTER\r
Via: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bKnashds8\r
Max-Forwards: 70\r
Contact: *
Expires: 0
Date: Thu, 21 Feb 2002 13:02:03 GMT\r
Content-Length: 0\r
`, n: 10,
		hf: HdrFromF | HdrToF | HdrCallIDF | HdrCSeqF | HdrOtherF |
			HdrContactF | HdrExpiresF | HdrCLenF,
		body: "", pf: SIPMsgSkipBodyF,
	},
	{m: `CANCEL sip:x@y.com SIP/2.0
From: <sip:b@foo.bar>;tag=1234\r
To:<sip:x@y.com>\r
Call-ID: a84b4c76e66710\r
From: Second From <x@q.b>;tag=5678\r
CSeq: 314159 INVITE\r
CSeq: 914159 CANCEL\r
Via: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bKnashds8\r
Max-Forwards: 70\r
Date: Thu, 21 Feb 2002 13:02:03 GMT\r
P-Asserted-Identity: "Test" <sip:b@foo.bar>\r
Contact: sip:a@foo.bar:5060,"A B" <sip:ab@x.y>;expires=60,\r
 <sip:foo.bar>;q=0.9\r
Expires: 300 \r
Content-Length: 568\r
`, n: 13,
		hf: HdrToF | HdrCallIDF | HdrFromF | HdrCSeqF | HdrOtherF |
			HdrPAIF | HdrContactF | HdrExpiresF | HdrCLenF,
		body: "", pf: SIPMsgSkipBodyF,
	},
	{m: `BYE sip:x@y.com SIP/2.0
From: <sip:b@foo.bar>;tag=1234\r
To:<sip:x@y.com>;tag=5678\r
Call-ID: a84b4c76e66710\r
From: Second From <sip:x@q.b>;tag=5678\r
CSeq: 914159 BYE\r
Via: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bKnashds8\r
Max-Forwards: 70\r
Date: Thu, 21 Feb 2002 13:02:03 GMT\r
P-Asserted-Identity: "Test" <sip:b@foo.bar>, tel:1234, "2nd" <sip:c@foo.bar>\r
Contact: sip:a@foo.bar:5060,"A B" <sip:ab@x.y>;expires=60,\r
 <sip:foo.bar>;q=0.9\r
Expires: 300 \r
Content-Length: 568\r
`, n: 12,
		hf: HdrToF | HdrCallIDF | HdrFromF | HdrCSeqF | HdrOtherF |
			HdrPAIF | HdrContactF | HdrExpiresF | HdrCLenF,
		body: "", pf: SIPMsgSkipBodyF,
	},
	{m: `SIP/2.0 200 Ok
From: <sip:b@foo.bar>;tag=1234\r
To:<sip:x@y.com>;tag=5678\r
Call-ID: a84b4c76e66710\r
From: Second From <x@q.b>;tag=5678\r
CSeq: 314159 INVITE\r
Via: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bKnashds8\r
Max-Forwards: 70\r
Date: Thu, 21 Feb 2002 13:02:03 GMT\r
P-Asserted-Identity: "Test" <sip:a@foo.bar>\r
P-Asserted-Identity: "Test" <sip:b@foo.bar>\r
P-Asserted-Identity: "Test" <sip:c@foo.bar>, tel:1234\r
Contact: sip:a@foo.bar:5060,"A B" <sip:ab@x.y>;expires=60,\r
 <sip:foo.bar>;q=0.9\r
Expires: 300 \r
Content-Length: 568\r
`, n: 14,
		hf: HdrToF | HdrCallIDF | HdrFromF | HdrCSeqF | HdrOtherF |
			HdrPAIF | HdrContactF | HdrExpiresF | HdrCLenF,
		body: "", pf: SIPMsgSkipBodyF,
	},

	{m: `INVITE sip:longbody@y.com SIP/2.0\r
From: <longbody@foo.bar>;tag=1234\r
To:<x@y.com>\r
Call-ID: a84b4c76e66710\r
CSeq: 314159 INVITE\r
Via: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bKnashds8\r
Max-Forwards: 70\r
Date: Thu, 21 Feb 2002 13:02:03 GMT\r
Content-Length: 1553\r
`, n: 8,
		hf: HdrFromF | HdrToF | HdrCallIDF | HdrCSeqF | HdrOtherF |
			HdrCLenF,
		body: `v=0\r
o=UserA 2890844526 2890844526 IN IP4 long.body.com\r
s=Session SDP\r
i= long description meaningless line 01 - space filler 70 characters\r
i= long description meaningless line 02 - space filler 70 characters\r
i= long description meaningless line 03 - space filler 70 characters\r
i= long description meaningless line 04 - space filler 70 characters\r
i= long description meaningless line 05 - space filler 70 characters\r
i= long description meaningless line 06 - space filler 70 characters\r
i= long description meaningless line 07 - space filler 70 characters\r
i= long description meaningless line 08 - space filler 70 characters\r
i= long description meaningless line 09 - space filler 70 characters\r
i= long description meaningless line 10 - space filler 70 characters\r
i= long description meaningless line 11 - space filler 70 characters\r
i= long description meaningless line 12 - space filler 70 characters\r
i= long description meaningless line 13 - space filler 70 characters\r
i= long description meaningless line 14 - space filler 70 characters\r
i= long description meaningless line 15 - space filler 70 characters\r
i= long description meaningless line 16 - space filler 70 characters\r
i= long description meaningless line 17 - space filler 70 characters\r
i= long description meaningless line 18 - space filler 70 characters\r
i= long description meaningless line 19 - space filler 70 characters\r
i= long description meaningless line 20 - space filler 70 characters\r
c=IN IP4 pc33.atlanta.com\r
t=0 0\r
m=audio 49172 RTP/AVP 0\r
a=rtpmap:0 PCMU/8000\r
`, /* len= 153 without i= lines, total 1541 */
	},
}

func TestParseMsg(t *testing.T) {

	offs := 0
	for _, c := range tests1 {
		buf := unescapeCRLF(c.m)
		buf = append(buf, '\r')
		buf = append(buf, '\n')
		if c.body != "" {
			body := unescapeCRLF(c.body)
			buf = append(buf, body...)
		}
		if c.offs == 0 {
			c.offs = len(buf)
		}
		testParseMsg(t, buf, offs, &c)
	}
}

func TestParseMsgPieces(t *testing.T) {

	offs := 0
	for _, c := range tests1 {
		buf := unescapeCRLF(c.m)
		buf = append(buf, '\r')
		buf = append(buf, '\n')
		if c.body != "" {
			body := unescapeCRLF(c.body)
			buf = append(buf, body...)
		}
		if c.offs == 0 {
			c.offs = len(buf)
		}
		testParseMsgPieces(t, buf, offs, &c, 20, 0)
	}
}

// tests segmented bodies (messages containing parital bodies)
// similar to TestParseMsgPieces but only the body part will be "split".
func TestParseMsgBodyPieces(t *testing.T) {

	offs := 0
	for _, c := range tests1 {
		if c.body == "" || (c.pf&SIPMsgSkipBodyF) != 0 {
			// skip over tests with no body or where body parsing is not
			// enabled
			continue
		}
		buf := unescapeCRLF(c.m)
		buf = append(buf, '\r')
		buf = append(buf, '\n')
		bodyOffs := len(buf)
		if c.body != "" {
			body := unescapeCRLF(c.body)
			buf = append(buf, body...)
		}
		if c.offs == 0 {
			c.offs = len(buf)
		}
		testParseMsgPieces(t, buf, offs, &c, 20, bodyOffs)
	}
}

func testParseMsg(t *testing.T, buf []byte, offs int, e *msgTest) {
	var msg PSIPMsg
	msg.Init(buf, nil, nil) // no extra hdrs or contacts
	testParseInitMsg(t, &msg, buf, offs, e)
}

func testParseInitMsg(t *testing.T, msg *PSIPMsg, buf []byte, offs int,
	e *msgTest) {
	var errChr string
	var parsed []byte
	pflags := e.pf
	o, err := ParseSIPMsg(buf, offs, msg, pflags)
	if err != e.err {
		if o >= 0 && o < len(buf) {
			errChr = string(buf[o])
			parsed = buf[:o]
		}
		t.Fatalf("ParseSIPMsg(%q, %d, ..)=[%d, %d(%q)]  error %s (%q)"+
			" expected (@ %q parsed: %q)",
			buf, offs, o, err, err, e.err, e.err, errChr, parsed)
	}
	if o != e.offs {
		t.Errorf("ParseSIPMsg(%q, %d, ..)=[%d, %d(%q)]  offset %d expected",
			buf, offs, o, err, err, e.offs)
		if o >= 0 && o < len(buf) {
			t.Errorf("parsed: %q\nMsg: %q\nBody: %q\n, Raw: %q\n",
				buf[:o], msg.Buf, msg.Body.Get(buf), msg.RawMsg)
		}
	}
	if msg.HL.N != e.n {
		t.Errorf("ParseSIPMsg(%q, %d, ..)=[%d, %d(%q)] %d headers instead of %d ",
			buf, offs, o, err, err, msg.HL.N, e.n)
	}
	if e.hf != 0 && msg.HL.PFlags != e.hf {
		t.Errorf("ParseSIPMsg(%q, %d, ..)=[%d, %d(%q)] 0x%x headers flags set"+
			"instead of 0x%x",
			buf, offs, o, err, err, msg.HL.PFlags, e.hf)
	}

	// WARNING: this test will not work if message does not start at
	// buf[0] (if there is some initial offset)
	if !bytes.Equal(msg.RawMsg, buf) {
		t.Errorf("ParseSIPMsg(%q, %d, ..)=[%d, %d(%q)] raw headers do not"+
			" match the expected value:\n  %q\n!=%q",
			buf, offs, o, err, err, msg.RawMsg, buf)
	}

	body := unescapeCRLF(e.body)
	if !bytes.Equal(msg.Body.Get(buf), body) {
		t.Errorf("ParseSIPMsg(%q, %d, ..)=[%d, %d(%q)] body does not match"+
			" the expected value:\n  %q\n!=%q",
			buf, offs, o, err, err, msg.Body.Get(buf), e.body)
	}
}

// simulate partial messages: breaks message in random pieces.
// Parameters:
// n - maximum number of message pieces (actual number: random between 0 and n)
// minOffs - start splitting the message only after minOffs bytes
func testParseMsgPieces(t *testing.T, buf []byte, offs int, e *msgTest,
	n int, minOffs int) {

	var msg PSIPMsg
	var err ErrorHdr
	o := offs
	pflags := e.pf
	pieces := rand.Intn(n)
	var sz, end int
	for i := 0; i < pieces; i++ {
		if end == 0 {
			// initial minimum endOffs
			if o < minOffs && minOffs < len(buf) {
				end = minOffs
			} else {
				end = o
			}
		}
		sz = rand.Intn(len(buf) + 1 - end)
		end += sz // always increase end
		if end < e.offs {
			if i == 0 {
				msg.Init(buf[:end], nil, nil) // no extra hdrs or contacts
			}
			t.Logf("piece %d/%d: [%d - %d] sz %d\n", i, pieces, o, end, sz)
			o, err = ParseSIPMsg(buf[:end], o, &msg, pflags)
			if err != ErrHdrMoreBytes {
				t.Errorf("ParseSIPMsg partial (%q, %d, ..)=[%d, %d(%q)] "+
					"  error %s (%q) expected",
					buf, offs, o, err, err, ErrHdrMoreBytes, ErrHdrMoreBytes)
			}
		} else {
			break
		}
	}
	t.Logf("pieces %d, rest [%d-%d] offs:%d minOffs: %d\n",
		pieces, o, len(buf), offs, minOffs)
	if pieces == 0 {
		msg.Init(buf, nil, nil) // no extra hdrs or contacts
	}
	// parse the rest
	testParseInitMsg(t, &msg, buf, o, e)
}
