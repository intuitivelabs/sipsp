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
	SigHasAtF     // @
	SigHasDotF    // .
	SigHasColonF  // :
	SigHasDashF   // -
	SigHasStarF   // *
	SigHasDivF    // /
	SigHasPlusF   // +
	SigHasEqF     // =
	SigHasUnderF  // _
	SigHasPipeF   // |
	SigHexEncF    // hex encoding
	SigB64EncF    // base 64 encoding
	SigDigBlocksF // composed of multiple digits blocks
)

// MsgSig contains the message signature.
type MsgSig struct {
	Method  SIPMethod
	CidSLen uint8    // call-id "short" length (w/o ip)
	CidSig  StrSigId // call-id sig
	FromSig StrSigId // from sig
	// CSeq      uint8    // cseq sig == range class - disabled, too random
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
		d := (uint32(s.FromSig) >> (4 * i)) & 0xf
		sb.WriteByte(hextable[int(d)])
	}
	/* cseq sig disabled: several UAs use random start CSeqs
	// add cseq
	sb.WriteByte('C')
	// 4 hex digits  flags
	for i := 1; i >= 0; i-- {
		d := (uint32(s.CSeq) >> (4 * i)) & 0xf
		sb.WriteByte(hextable[int(d)])
	}
	*/
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

	// cseq sig == cseq value range
	/* cseq sig disabled, start cseq is often a random value
	cseq := msg.PV.GetCSeq().CSeqNo
	if cseq < 10000 {
		sig.CSeq = uint8(cseq / 100)
	} else if cseq < 100000 {
		sig.CSeq = 100 + uint8((cseq-10000)/1000)
	} else if cseq < 740000 {
		sig.CSeq = 190 + uint8((cseq-100000)/10000)
	} else {
		sig.CSeq = 0xff // really big start value
	}
	*/

	// hdr sigs
	var seen HdrFlags
	sig.HdrSigLen = 0
	for _, h := range msg.HL.Hdrs {
		// add to sig only the first hdr occurence
		if !seen.Test(h.Type) {
			seen.Set(h.Type)
			s, err := GetHdrSigId(h)
			// skip over Contact for non-Invites (it's optional even for
			// REGs, e.g. reg-fetch)
			if err == ErrHdrOk &&
				(h.Type != HdrContact || sig.Method == MInvite) {
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

func resCharSigFlag(c byte) (sig StrSigId) {
	switch c {
	case '@':
		sig |= SigHasAtF
	case '.':
		sig |= SigHasDotF
	case ':':
		sig |= SigHasColonF
	case '-':
		sig |= SigHasDashF
	case '_':
		sig |= SigHasUnderF
	case '*':
		sig |= SigHasStarF
	case '+':
		sig |= SigHasPlusF
	case '/':
		sig |= SigHasDivF
	case '=':
		sig |= SigHasEqF
	case '|':
		sig |= SigHasPipeF
	}
	return
}

func getStrCharsSig(s []byte, skipOffs, skipLen int) StrSigId {
	var sig StrSigId
	var sep byte // separator (if found)
	var sepNo int
	bstart := 0 // current digit block start
	base64 := true
	hex := true
	dec := true
	fLowerCase := false
	fUpperCase := false
	skipChrs := 0 // extra chars skipped
	for i := 0; i < len(s); i++ {
		if i >= skipOffs && i < (skipOffs+skipLen) {
			// ignore this part
			continue
		}
		if i == skipOffs+skipLen {
			bstart = i // start  a new digit block after the ip
		}
		if f := resCharSigFlag(s[i]); f != 0 {
			sig |= f
			// ip@something -> ignore '@' or other reserved char immediately
			// after an ip, in hex or base64 guessing
			if (skipLen == 0) ||
				(i != skipOffs+skipLen && i != (skipOffs-1)) {
				// not immediately after or before an ip
				if base64 && !(s[i] == '+' || s[i] == '/' || s[i] == '=') {
					// special char different from + / =  => not base64
					base64 = false
				} else if base64 && s[i] == '=' {
					// valid base64, but only as the last 2 padding chars
					if !((i == len(s)-1) ||
						(i == (len(s)-2) && s[i+1] == '=')) {
						// not last or last 2 not '='
						base64 = false
					}
				}
				if sep == 0 {
					sep = s[i]
					sepNo++
				} else if sep == s[i] {
					sepNo++
				}
				if i > 0 {
					if sep != s[i] || (i <= bstart) {
						// different sep found or 2 seps in a row =>
						// format is not block separated dec or hex
						dec = false
						hex = false
					} else if sep == s[i] &&
						((i > bstart) && ((i-bstart)%2 != 0)) {
						// block between separators found, but odd length
						// => not hex
						hex = false
					}
				}
				bstart = i + 1 // start  new block after delim.
			} else {
				//  immediately after or before  an ip (skip portion)
				// char just before ip or immediately after ip
				if i == skipOffs+skipLen {
					// first char after ip -> ignore
					bstart = i + 1 // next digit block start after ip delim
				}
				skipChrs++
			}
		} else if !(s[i] >= '0' && s[i] <= '9') {
			dec = false
			if !((s[i] >= 'A' && s[i] <= 'F') ||
				(s[i] >= 'a' && s[i] <= 'f')) {
				hex = false
				if !((s[i] >= 'E' && s[i] <= 'Z') ||
					(s[i] >= 'e' && s[i] <= 'z')) {
					base64 = false
				}
			}
			if s[i] >= 'a' && s[i] <= 'z' {
				fLowerCase = true
			} else if s[i] >= 'A' && s[i] <= 'Z' {
				fUpperCase = true
			}
		}
	}
	l := len(s) - skipLen - skipChrs - sepNo
	blen := len(s) - bstart
	// guess encoding only if enough chars
	if l >= 10 {
		// ignore decimal only for now, too high risk of confusing it with hex

		// hex encoding if only hex range found, len multiple of 2 and no
		// mixed case (mixed case => probably base64)
		if (dec || hex) &&
			((sep == 0 && l%2 == 0) ||
				(sep != 0 && blen >= 0 && (blen%2 == 0))) &&
			!(fLowerCase && fUpperCase) {
			sig |= SigHexEncF
			if sep != 0 {
				sig |= SigDigBlocksF
			}
		} else if base64 && (l%4 == 0) {
			// ignore base64 encoding that skip padding (for now)
			sig |= SigB64EncF
		}
	}
	return sig
}

// GetCallIDSig returns a call-id sig and a sig len (call-id lenght w/o ip).
func GetCallIDSig(cid []byte) (StrSigId, uint8) {
	// check if callid contains an ip
	var ipOffs, ipLen int
	var sig StrSigId
	hasIP, ipOffs, ipLen := ContainsIP4(cid, nil)
	if !hasIP {
		hasIP, ipOffs, ipLen = ContainsIP6(cid, nil)
	}
	if hasIP {
		if ipOffs == 0 {
			sig |= SigIPStartF
		} else if (ipOffs + ipLen) == len(cid) {
			sig |= SigIPEndF
		} else {
			sig |= SigIPMiddleF
		}
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
