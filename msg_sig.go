// Copyright 2022 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

package sipsp

import (
	"fmt"
	"strings"
)

// header order signature includes the following headers:
// Call-ID, Contact (INV req only, ?REG), CSeq, From, Max-Forwads (req),
// To, Via (1st, req), User-Agent
// header signature format: method | header_sig_id ...
// where header_sig_id = compact/long | header_num_id

// HdrSigId contains the header id used in a message header signature.
// Format: size | header_num_id, where size is 1 bit: 0 for normal,
//         1 for compact
type HdrSigId uint8

// headers included in the signature
var sigHdrs = [...]HdrT{
	HdrCallID,
	HdrContact,
	HdrCSeq,
	HdrFrom,
	HdrMaxFwd,
	HdrTo,
	HdrVia,
	HdrUA,
}

// maps HdrT to HdrSigId
var hdr2SigId [HdrOther + 1]HdrSigId

const NoSigHdrs = len(sigHdrs)

// flags set for all headers we are looking for generating a sig
var sigHdrsFlags HdrFlags

// mask for the compact format bit in the hdr. sig id
const HdrSigIdCMask = 0x8

func init() {
	// fill hdr2SigId
nxt_hdr_t:
	for t := int(HdrNone); t <= int(HdrOther); t++ {
		for i, s := range sigHdrs {
			if s == HdrT(t) {
				hdr2SigId[t] = HdrSigId(i)
				continue nxt_hdr_t
			}
		}
		// not found => no sig
		hdr2SigId[t] = HdrSigId(0xff)
	}
	// fill sigHdrsFlags
	for _, s := range sigHdrs {
		sigHdrsFlags.Set(s)
	}

	if HdrSigIdCMask < len(sigHdrs) {
		panic(fmt.Sprintf(
			"bad HdrSigIdCMask mask value %d (%d hdrs used for sig)\n",
			HdrSigIdCMask, len(sigHdrs)))
	}
}

// GetHdrSigId returns the header signature id for the header h.
// On error (header has no signature id) , it returns HdrSigId(255) and
// ErrHdrBad.
func GetHdrSigId(h Hdr) (HdrSigId, ErrorHdr) {
	if int(h.Type) >= len(hdr2SigId) || int(h.Type) < 0 {
		BUG("unsupported header type %d (%q) max %d\n",
			h.Type, h.Type, len(hdr2SigId))
		return 0xff, ErrHdrBug
	}
	if s := hdr2SigId[int(h.Type)]; s != 0xff {
		if h.Name.Len == 1 {
			// compact header
			return HdrSigIdCMask | s, ErrHdrOk
		}
		return s, ErrHdrOk
	}
	return 0xff, ErrHdrBad
}

// StrSigId contains a signature for some string (e.g. call-id content)
type StrSigId uint16

const (
	SigIPStartF StrSigId = 1 << iota
	SigIPEndF
	SigIPMiddleF
	SigHasAtF    // @
	SigHasDotF   // .
	SigHasColonF // :
	SigHasEqF    // =
	SigHasDashF  // -
	SigHasUnderF // _
)

// MsgSig contains the message signature.
type MsgSig struct {
	Method    SIPMethod
	CidSLen   uint8    // call-id "short" length (w/o ip)
	CidSig    StrSigId // call-id sig
	FromSig   StrSigId // from sig
	HdrSig    [NoSigHdrs]HdrSigId
	HdrSigLen int // number of entries in HdrSig
}

// String() returns the string format for s, mostly for debugging.
// Format: hex string -- method hdr_sig_id... C cid_sig cid_len F from_sig ,
//         method & hdr_sig_id are represented by a single hex digit
//         cid_sig is 4 digits (16 bits)
//         cid_len is 2 digits  (8 bit)
//         from_sig is 4 digits  (16 bits)
func (s MsgSig) String() string {
	const hextable = "0123456789abcdef"
	var sb strings.Builder
	if s.Method == MUndef && s.HdrSigLen == 0 {
		return ""
	}
	// method
	if int(s.Method) >= 16 {
		sb.WriteByte('E') // error
		BUG("method number exceed string charset encoding range: %d\n",
			s.Method)
	}
	sb.WriteByte(hextable[int(s.Method)&0xf])
	// hdr order sig
	for i := 0; i < s.HdrSigLen; i++ {
		if int(s.HdrSig[i]) >= 16 {
			BUG("header sig[%d] exceed string charset encoding range: %d\n",
				i, s.HdrSig[i])
			sb.WriteByte('E') // error
		}
		sb.WriteByte(hextable[int(s.HdrSig[i])&0xf])
	}

	// add callid
	sb.WriteByte('I')
	// 4 hex digits  flags
	for i := 3; i >= 0; i-- {
		d := (uint32(s.CidSig) >> (4 * i)) & 0xf
		sb.WriteByte(hextable[int(d)])
	}
	// 2 hex digits  len
	sb.WriteByte(hextable[int((s.CidSLen>>4)&0xf)])
	sb.WriteByte(hextable[int(s.CidSLen&0xf)])

	// add from
	sb.WriteByte('F')
	// 4 hex digits  flags
	for i := 3; i >= 0; i-- {
		d := (uint32(s.CidSig) >> (4 * i)) & 0xf
		sb.WriteByte(hextable[int(d)])
	}
	return sb.String()
}

// GetMsgSig returns a MsgSig structure containing the message signature.
// It returns ErrHdrOk in success, ErrHdrTrunc if not all the message
// headers were inspected (msg.HL.Hdrs is too small and does not contain
// all the interesting headers) and ErrHdrEmpty if no signature could
// be generated (in which case the returned MsgSigT should be ignored, e.g.
// for a reply)
func GetMsgSig(msg *PSIPMsg) (MsgSig, ErrorHdr) {
	var sig MsgSig

	if !msg.Request() {
		return sig, ErrHdrEmpty // no sig, not request
	}
	sig.Method = msg.FL.MethodNo
	// call-id
	cid := msg.PV.GetCallID().CallID.Get(msg.Buf)
	sig.CidSig, sig.CidSLen = GetCallIDSig(cid)
	// from-tag
	sig.FromSig = getStrCharsSig(msg.PV.GetFrom().Tag.Get(msg.Buf), 0, 0)
	// hdr sigs
	var seen HdrFlags
	sig.HdrSigLen = 0
	for _, h := range msg.HL.Hdrs {
		// add to sig only the first hdr occurence
		if !seen.Test(h.Type) {
			seen.Set(h.Type)
			s, err := GetHdrSigId(h)
			if err == ErrHdrOk {
				sig.HdrSig[sig.HdrSigLen] = s
				sig.HdrSigLen++
				if sig.HdrSigLen >= len(sig.HdrSig) {
					// all hdrs we are interested in already found
					return sig, ErrHdrOk
				}
			}
			if (msg.HL.PFlags & sigHdrsFlags) == seen {
				// already seen all the interesting headers in the message
				return sig, ErrHdrOk
			}
		}
	}
	if msg.HL.N > len(msg.HL.Hdrs) {
		// not all headers seen, did not fit in msg.HL.Hdrs
		DBG("trunc headers: msg has %d but space for %d\n", msg.HL.N, len(msg.HL.Hdrs))
		return sig, ErrHdrTrunc
	}
	return sig, ErrHdrOk
}

func getStrCharsSig(s []byte, skipOffs, skipLen int) StrSigId {
	var sig StrSigId
	for i := 0; i < len(s); i++ {
		if i >= skipOffs && i < (skipOffs+skipLen) {
			// ignore this part
			continue
		}
		switch s[i] {
		case '@':
			sig |= SigHasAtF
		case '.':
			sig |= SigHasDotF
		case ':':
			sig |= SigHasColonF
		case '=':
			sig |= SigHasEqF
		case '-':
			sig |= SigHasDashF
		case '_':
			sig |= SigHasUnderF
		}
	}
	return sig
}

// GetCallIDSig returns a call-id sig and a sig len (call-id lenght w/o ip).
func GetCallIDSig(cid []byte) (StrSigId, uint8) {
	// check if callid contains an ip
	var ipOffs, ipLen int
	var sig StrSigId
	if ok, ipOffs, ipLen := ContainsIP4(cid, nil); ok {
		if ipOffs == 0 {
			sig |= SigIPStartF
		} else if (ipOffs + ipLen) == len(cid) {
			sig |= SigIPEndF
		} else {
			sig |= SigIPMiddleF
		}
	} else {
		// TODO: try ipv6
	}
	// look for special chars, skipping over the ip
	sig |= getStrCharsSig(cid, ipOffs, ipLen)
	// add len
	clen := len(cid) - ipLen
	if clen > 0xff {
		// excesive  lenghts are represented by 0xff
		clen = 0xff
	}
	// limit len to max 1023
	// sig format: 16 bit flags | 4 bit reserved |  12 bits trunc. length
	// sig = sig<<16 | (StrSigId(clen) & 0x0fff)
	return sig, uint8(clen & 0xff)
}
