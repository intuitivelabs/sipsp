package calltr

import (
	"bytes"
	//	"fmt"
	"net"
	// "sync"
	"strconv" // dbg
	"sync/atomic"
	"time"

	"andrei/sipsp"
)

const (
	MaxTagSpace         = 384 // maximum space reserved for callid + fromtag + totag
	MinTagLen           = 32  // minimum space reserved for tags
	DefaultTagLen       = 50  // space reserved for totag
	DefaultToTagLen     = DefaultTagLen
	DefaultFromTagLen   = DefaultTagLen
	MaxURISpace         = 96 // max uri size for saving to-uri, from-uri and r-uri
	DefaultURISpace     = 64 // in case an uri size is not yet known, reserve...
	MaxMethodSpace      = 16 // max space for saving method
	DefaultMethodSpace  = 16
	MaxReasonSpace      = 64 // max space for saving a reply reason
	DefaultReasonSpace  = 64 // if reason not known yet, reserve ...
	MinReasonSpace      = 64
	MaxContactSpace     = 160 // max space for saving contacts
	DefaultContactSpace = 64  // if contact not known yet, reserve...
	MaxUASpace          = 64  // max sace for saving UA (from UAC or UAS)
	DefaultUACSpace     = 64
	DefaultUASSpace     = 48
	HashSize            = 65536
)

type CallKey struct {
	buf     []byte       // CallID, FromTag & ToTag point to data stored here
	CallID  sipsp.PField // use PField since they are more compact
	FromTag sipsp.PField
	ToTag   sipsp.PField
}

func (c *CallKey) GetCallID() []byte {
	return c.CallID.Get(c.buf)
}

func (c *CallKey) GetFromTag() []byte {
	return c.FromTag.Get(c.buf)
}

func (c *CallKey) GetToTag() []byte {
	return c.ToTag.Get(c.buf)
}

// Reset() keeps the buffer
func (c *CallKey) Reset() {
	buf := c.buf
	*c = CallKey{}
	c.buf = buf
}

// Init() initializes a CallKey structures and set the initial buffer
func (c *CallKey) Init(b []byte) {
	c.Reset()
	c.buf = b
}

// SetCF sets the callid and the fromtag.
// It returns true if it succeeds and false on error (not enough space to
// copy the values and keep reserve bytes free for the totag)
func (c *CallKey) SetCF(callid, fromtag []byte, reserve int) bool {
	maxl := len(c.buf)
	callidLen := len(callid)
	fromtagLen := len(fromtag)
	if fromtagLen == 0 {
		fromtagLen = DefaultFromTagLen
	}
	if callidLen+fromtagLen+reserve > maxl {
		DBG("SetCF(l:%d, l:%d, %d) failed max len %d\n",
			callidLen, fromtagLen, reserve, maxl)
		return false
	}
	copy(c.buf[:], callid)
	c.CallID.Set(0, callidLen)
	copy(c.buf[callidLen:], fromtag)
	c.FromTag.Set(callidLen, callidLen+len(fromtag))
	c.ToTag.Set(callidLen+len(fromtag), callidLen+len(fromtag))
	return true
}

// TagSpace returns true if there is enough space for a from tag and a
// to tag of the given lengths. It assumes the callid was already set.
func (c *CallKey) TagSpace(fTagLen, tTagLen int) bool {
	fTagOffs := (int)(c.CallID.Offs + c.CallID.Len)
	maxl := len(c.buf) - fTagOffs
	if fTagLen+tTagLen > maxl {
		return false
	}
	return true
}

// SetFTag sets/replaces the fromtag. It assumes the callid was already set.
// It returns true if it succeeds and false on error (not enough space to
// copy the values and keep reserve bytes free for the to tag)
func (c *CallKey) SetFTag(fromtag []byte, reserve int) bool {
	fTagOffs := (int)(c.CallID.Offs + c.CallID.Len)
	newFTagLen := len(fromtag)
	if newFTagLen == 0 {
		newFTagLen = DefaultFromTagLen
	}
	if c.TagSpace(newFTagLen, reserve) == false {
		return false
	}
	copy(c.buf[fTagOffs:], fromtag)
	c.FromTag.Set(fTagOffs, fTagOffs+len(fromtag))
	c.ToTag.Set(fTagOffs+len(fromtag), fTagOffs+len(fromtag))
	return true
}

// Key() returns the actual key
func (c *CallKey) Key() []byte {
	return c.CallID.Get(c.buf)
}

// SetToTag sets the totag, but only if the callid and fromtag are set.
// On error it returns false (if the callid or fromtag are not set or if
// there is not enough space to  copy the totag).
func (c *CallKey) SetToTag(totag []byte) bool {
	maxl := len(c.buf)
	callidLen := int(c.CallID.Len)
	fromtagLen := int(c.FromTag.Len)
	totagLen := len(totag)
	// allow empty fromtag (consider it equivalent to fromtag="")
	if callidLen == 0 /*|| fromtagLen == 0*/ {
		DBG("CallKey: SetToTag (%d bytes): empty callid(%d),  fromtag: %d\n",
			totagLen, callidLen, fromtagLen)
		return false
	}
	if callidLen+fromtagLen+totagLen > maxl {
		DBG("CallKey: SetToTag (%d bytes): key exceeds maximum (%d/%d):"+
			" callid(%d) or fromtag(%d)\n",
			totagLen, maxl, callidLen+fromtagLen+totagLen,
			callidLen, fromtagLen)
		return false
	}
	copy(c.buf[callidLen+fromtagLen:], totag)
	c.ToTag.Set(callidLen+fromtagLen, callidLen+fromtagLen+totagLen)
	return true
}

type CallState uint8

const (
	CallStNone CallState = iota
	CallStInit
	CallStFInv // first invite
	CallStEarlyDlg
	CallStNegReply
	CallStEstablished
	CallStBye
	CallStByeReplied
	CallStCanceled
	CallStFNonInv // first non-invite
	CallStNonInvNegReply
	CallStNonInvFinished
)

// per state timeout in S
var stateTimeoutS = [...]uint{
	CallStNone:           1,
	CallStInit:           1,
	CallStFInv:           120,
	CallStEarlyDlg:       180,
	CallStNegReply:       30,
	CallStEstablished:    3600,
	CallStBye:            30,
	CallStByeReplied:     5,
	CallStCanceled:       5,
	CallStFNonInv:        30,
	CallStNonInvNegReply: 5,
	CallStNonInvFinished: 5,
}

var callSt2String = [...]string{
	CallStNone:           "invalid",
	CallStInit:           "init",
	CallStFInv:           "first invite",
	CallStEarlyDlg:       "early dialog",
	CallStNegReply:       "invite negative reply",
	CallStEstablished:    "established",
	CallStBye:            "bye detected",
	CallStByeReplied:     "bye replied",
	CallStCanceled:       "canceled",
	CallStFNonInv:        "initial non-invite",
	CallStNonInvNegReply: "non-invite negative reply",
	CallStNonInvFinished: "non-invite finished",
}

func (s CallState) String() string {
	if int(s) >= len(callSt2String) {
		return "bug - unknown state"
	}
	return callSt2String[s]
}

func (s CallState) TimeoutS() uint {
	if int(s) >= len(stateTimeoutS) {
		return 0
	}
	return stateTimeoutS[s]
}

type CallFlags uint8

const (
	CFHashed          CallFlags = 1 << iota
	CFReused                    // entry re-use instead of forking
	CFRegReplacedHack           // REGISTER re-use hack
	CFForkChild
	CFForkParent
	CFCanceled       // CANCEL seem
	CFInternalCancel // fin reply recv on some branch: internal cancel
	CFTimeout
)

// debugging, keep in sync with the CallFlags consts above
var cfNames = [...]string{
	"Entry_Hashed",
	"Reused",
	"REG_Reuse_Hack",
	"Fork_Child",
	"Fork_Parent",
	"Canceled",
	"Internal_Cancel",
	"Timeout",
	"invalid",
	"invalid",
	"invalid",
}

func (cf CallFlags) String() string {
	var s string
	for i := 1; i < len(cfNames); i++ {
		if cf&(1<<uint(i)) != 0 {
			if s != "" {
				s += "|" + cfNames[i]
			} else {
				s += cfNames[i]
			}
		}
	}
	return s
}

type CallAttrIdx uint8

const (
	AttrFromURI CallAttrIdx = iota
	AttrToURI
	AttrMethod
	AttrRURI
	AttrContact
	AttrReason
	AttrUA
	AttrUAS
	AttrLast
)

var callAttrTStr = [...]string{
	AttrFromURI: "sip.from",
	AttrToURI:   "sip.to",
	AttrMethod:  "sip.request.method", // initial message method as "string"
	AttrRURI:    "uri.original",
	AttrContact: "sip.contact",         // contact header contents
	AttrReason:  "sip.sip_reason",      // winning reply reason
	AttrUA:      "user_agent.original", // from-ua / uac
	AttrUAS:     "uas.original",        // server/remote-side UA
	AttrLast:    "invalid",
}

func (a CallAttrIdx) String() string {
	if int(a) >= len(callAttrTStr) || int(a) < 0 {
		return callAttrTStr[AttrLast]
	}
	return callAttrTStr[a]
}

type AttrLenRange struct {
	Min     uint
	Max     uint
	Default uint
}

var AttrSpace = [AttrLast]AttrLenRange{
	AttrFromURI: {0, MaxURISpace, DefaultURISpace},
	AttrToURI:   {0, MaxURISpace, DefaultURISpace},
	AttrMethod:  {0, MaxMethodSpace, DefaultMethodSpace},
	AttrRURI:    {0, MaxURISpace, DefaultURISpace},
	AttrContact: {0, MaxContactSpace, DefaultContactSpace},
	AttrReason:  {MinReasonSpace, MaxReasonSpace, DefaultReasonSpace},
	AttrUA:      {0, MaxUASpace, DefaultUACSpace},
	AttrUAS:     {0, MaxUASpace, DefaultUASSpace},
}

// CallInfo contains extra call information for event generation.
// It's not needed/used for pure call state tracing.
type CallInfo struct {
	Attrs [AttrLast]sipsp.PField
	used  int    // used bytes in buf / current append offset
	buf   []byte // all the above PFields point here
}

// Reset keeping internal storage buffer
func (ci *CallInfo) Reset() {
	buf := ci.buf
	*ci = CallInfo{}
	ci.buf = buf
}

func (ci *CallInfo) Init(b []byte) {
	ci.Reset()
	ci.buf = b
}

func (ci *CallInfo) GetAttrField(i CallAttrIdx) *sipsp.PField {
	if int(i) >= len(ci.Attrs) || int(i) < 0 {
		return nil
	}
	return &ci.Attrs[i]
}

func (ci *CallInfo) AddAttrField(i CallAttrIdx, v *sipsp.PField, buf []byte) int {
	return addPField(v, buf, &ci.Attrs[i], &ci.buf, &ci.used,
		int(AttrSpace[i].Max))
}

func (ci *CallInfo) AddAttr(i CallAttrIdx, v []byte) int {
	return addSlice(v, &ci.Attrs[i], &ci.buf, &ci.used,
		int(AttrSpace[i].Max))
}

// append a pfield in the Callinfo buf, without setting an attr to it
// returns number of bytes added
func (ci *CallInfo) AppendPField(v *sipsp.PField, buf []byte, dst *sipsp.PField) int {
	return addPField(v, buf, dst, &ci.buf, &ci.used, 0)
}

// "delete" an attribut, freeing its used space (shifts all attrs above it)
func (ci *CallInfo) DelAttr(i CallAttrIdx) {

	l := int(ci.Attrs[i].Len)
	if l == 0 {
		return
	}
	offs := int(ci.Attrs[i].Offs)
	copy(ci.buf[offs:], ci.buf[offs+l:ci.used])
	ci.used -= l
	ci.Attrs[i].Reset()
	// update the offset of everything above offs
	for n := 0; n < len(ci.Attrs); n++ {
		if int(ci.Attrs[n].Offs) >= offs {
			ci.Attrs[n].Offs -= sipsp.OffsT(l)
		}
	}
}

func (ci *CallInfo) OverwriteAttrField(i CallAttrIdx, v *sipsp.PField, buf []byte) int {
	return ci.OverwriteAttr(i, v.Get(buf))
}

// overwrite an already set attr
func (ci *CallInfo) OverwriteAttr(i CallAttrIdx, b []byte) int {
	ret := ci.AddAttr(i, b)
	if ret != -1 {
		// not already present => added
		return ret
	}
	// overwrite
	l := int(fixLen(uint(len(b)), 0, 0, AttrSpace[i].Max))
	if l <= int(ci.Attrs[i].Len) {
		oldLen := int(ci.Attrs[i].Len)
		copy(ci.buf[int(ci.Attrs[i].Offs):], b[:l])
		offs := int(ci.Attrs[i].Offs) + l
		ci.Attrs[i].Set(int(ci.Attrs[i].Offs), offs)
		// we have a hole of oldLen -len bytes
		diff := oldLen - l
		copy(ci.buf[offs:], ci.buf[offs+diff:ci.used])
		ci.used -= diff
		// update the offset of everything above old attr end (offs = Offs +l)
		for n := 0; n < len(ci.Attrs); n++ {
			if int(ci.Attrs[n].Offs) >= offs {
				ci.Attrs[n].Offs -= sipsp.OffsT(diff)
			}
		}
		return l
	}
	// if we are here there is not enough space to "replace in place",
	// try adding at the end
	ci.DelAttr(i)
	return ci.AddAttr(i, b)
}

func (ci *CallInfo) GetAttrVal(i CallAttrIdx) []byte {
	if v := ci.GetAttrField(i); v != nil {
		return v.Get(ci.buf)
	}
	return nil
}

// returns true on success (fully added) and false on partial add or
// failure (already set)
func (ci *CallInfo) AddMethod(v *sipsp.PField, buf []byte) bool {
	n := ci.AddAttrField(AttrMethod, v, buf)
	return n == int(v.Len)
}

// helper function: fills src array with corresp. values from the sip msg.
func FillAttrsSrc(m *sipsp.PSIPMsg, dir int, src *[AttrLast]*sipsp.PField) {
	if m.Request() {
		if dir == 0 {
			src[AttrFromURI] = &m.PV.From.URI
			src[AttrToURI] = &m.PV.To.URI
			src[AttrMethod] = &m.FL.Method
			src[AttrRURI] = &m.FL.URI
			// get 1st contact uri
			cv := m.PV.Contacts.GetContact(0)
			if cv != nil {
				src[AttrContact] = &cv.URI
			} else {
				src[AttrContact] = nil
			}
			src[AttrReason] = nil
			src[AttrUA] = &m.HL.GetHdr(sipsp.HdrUA).Val
			src[AttrUAS] = nil
		} else {
			src[AttrFromURI] = &m.PV.To.URI
			src[AttrToURI] = &m.PV.From.URI
			src[AttrMethod] = nil
			src[AttrRURI] = nil
			src[AttrContact] = nil
			src[AttrReason] = nil
			src[AttrUA] = nil
			src[AttrUAS] = &m.HL.GetHdr(sipsp.HdrUA).Val
		}
	} else {
		if dir == 0 {
			src[AttrFromURI] = &m.PV.From.URI
			src[AttrToURI] = &m.PV.To.URI
			src[AttrMethod] = &m.PV.CSeq.Method
			src[AttrRURI] = nil
			if m.Method() == sipsp.MRegister && m.FL.Status >= 200 {
				cv := m.PV.Contacts.GetContact(0)
				if cv != nil {
					src[AttrContact] = &cv.URI
				} else {
					src[AttrContact] = nil
				}
			} else {
				src[AttrContact] = nil
			}
			src[AttrReason] = &m.FL.Reason
			src[AttrUA] = nil
			src[AttrUAS] = &m.HL.GetHdr(sipsp.HdrUA).Val
		} else {
			src[AttrFromURI] = &m.PV.To.URI
			src[AttrToURI] = &m.PV.From.URI
			src[AttrMethod] = nil
			src[AttrRURI] = nil
			if m.Method() != sipsp.MRegister {
				cv := m.PV.Contacts.GetContact(0)
				if cv != nil {
					src[AttrContact] = &cv.URI
				} else {
					src[AttrContact] = nil
				}
			} else {
				src[AttrContact] = nil
			}
			src[AttrReason] = nil
			src[AttrUA] = &m.HL.GetHdr(sipsp.HdrUA).Val
			src[AttrUAS] = nil
		}
	}
}

func (ci *CallInfo) AddFromMsg(m *sipsp.PSIPMsg, dir int) int {

	var s int
	type dstField struct {
		v   *sipsp.PField
		max int
	}
	var src [AttrLast]*sipsp.PField
	FillAttrsSrc(m, dir, &src)
	for i := 0; i < len(src); i++ {
		if src[i] == nil {
			continue
		}
		//fmt.Printf("SetFromMsg: addPField src[%d - %s]: %v, len(m.Buf)= %d\n", i, CallAttrIdx(i), *src[i], len(m.Buf))
		n := addPField(src[i], m.Buf, &ci.Attrs[i], &ci.buf, &ci.used,
			int(AttrSpace[i].Max))
		//fmt.Printf("SetFromMsg: addPField dst[%d]: %v, len(ci.buf)= %d (%d)\n", i, ci.Attrs[i], len(ci.buf), ci.used)
		if n > 0 {
			s += n
		}
	}
	return s
}

// Set / copy attrinbutes from another callinfo, ignoring attributes that
// are already set.
func (ci *CallInfo) AddFromCi(si *CallInfo) int {
	ret := 0
	for i := 0; i < len(ci.Attrs); i++ {
		if si.Attrs[i].Empty() {
			continue
		}
		//fmt.Printf("SetFromCi: addPField si.Attrs[%d - %s]: %v, len(si.buf)= %d (%d)\n", i, CallAttrIdx(i), si.Attrs[i], len(si.buf), si.used)
		n := ci.AddAttrField(CallAttrIdx(i), &si.Attrs[i], si.buf)
		if n > 0 {
			ret += n
		}
	}
	return ret
}

// returns max if a > max, min if a < min and def if a == 0 and def between
// min and max
func fixLen(a, def, min, max uint) uint {
	if a == 0 {
		a = def
	}
	if a > max {
		return max
	}
	if a < min {
		return min
	}
	return a
}

func infoReserveSize(m *sipsp.PSIPMsg, dir int) uint {
	var sz uint
	var src [AttrLast]*sipsp.PField
	FillAttrsSrc(m, dir, &src)
	for i := 0; i < len(src); i++ {
		if src[i] == nil {
			sz += AttrSpace[i].Default
		} else {
			sz += fixLen(uint(src[i].Len),
				AttrSpace[i].Default, AttrSpace[i].Min, AttrSpace[i].Max)
		}
	}
	return sz
}

// Copies a PField with accompanying buffer to another PField, buffer, offset.
// Returns number of bytes added (limited by max) and -1 on error (dstP
// not empty). It increases offs (by the number of bytes added).
// If the destination PField is not empty (Len != 0) it will return error.
func addPField(srcP *sipsp.PField, sbuf []byte, dstP *sipsp.PField, dbuf *[]byte, offs *int, max int) int {

	/*	if dstP.Len != 0 {
			return -1 // already added
		}
		sLen := int(srcP.Len)
		if max >= 0 && sLen > max {
			sLen = max // truncate to <max>
		}
		n := copy((*dbuf)[*offs:], srcP.Get(sbuf)[:sLen])
		dstP.Set(*offs, n+*offs)
		*offs += n
		return n
	*/
	return addSlice(srcP.Get(sbuf), dstP, dbuf, offs, max)
}

// Copies a slice to destination buffer, at offset offs and sets a
// PField to point to it.
// Returns number of bytes added (limited by max) and -1 on error (dstP
// not empty). It increases offs (by the number of bytes added).
// If the destination PField is not empty (Len != 0) it will return error.
func addSlice(src []byte, dstP *sipsp.PField, dbuf *[]byte, offs *int, max int) int {

	if dstP.Len != 0 {
		return -1 // already added
	}
	sLen := len(src)
	if max >= 0 && sLen > max {
		sLen = max // truncate to <max>
	}
	n := copy((*dbuf)[*offs:], src[:sLen])
	dstP.Set(*offs, n+*offs)
	*offs += n
	return n
}

// record message type and direction
// TODO: move it in a separate file and conditional compile
// format: last bit (15) -> direction, 0 caller -callee or 1 (reverse)
//              bit 14   -> type: 0 request, 1 reply
//              bit 13-10 -> retransmission no. 0 == no retr, max 16)
//              bits 0-9 -> reply status , if type == 1
//              bit 0-8  -> request method no. if type == 0
type MsgRec uint16

const (
	MsgRecDir1F      = 1 << 15
	MsgRecReplF      = 1 << 14
	MsgRecRetrPos    = 10
	MsgRecRetrMask   = 0x3c00
	MsgRecMaxRetr    = MsgRecRetrMask >> MsgRecRetrPos
	MsgRecMethodMask = 0xff
	MsgRecStatusMask = 0x03ff
)

func (m *MsgRec) InitReq(method sipsp.SIPMethod, dir, retr int) {
	*m = MsgRec(uint16(method) | uint16(dir<<15) |
		(uint16(retr<<MsgRecRetrPos) & MsgRecRetrMask))
}

func (m *MsgRec) InitRepl(status uint16, dir, retr int) {
	*m = MsgRec(status | uint16(dir<<15) |
		(uint16(retr<<MsgRecRetrPos) & MsgRecRetrMask) | MsgRecReplF)
}

func (m *MsgRec) Retrs() int {
	retrs := (uint(*m) & MsgRecRetrMask) >> MsgRecRetrPos
	return int(retrs)
}

func (m *MsgRec) SetRetrs(retr int) {
	*m = MsgRec((uint16(*m) &^ MsgRecRetrMask) |
		(uint16(retr<<MsgRecRetrPos) & MsgRecRetrMask))
}

func (m *MsgRec) String() string {
	var str string
	if (*m&MsgRecDir1F != 0) != (*m&MsgRecReplF != 0) {
		// if dir  & repl diff (e.g. 0 1 or 1 0)
		str = "<"
	} else {
		// if dir & repl same
		str = ">"
	}
	/*
		if *m&MsgRecRetrMask != 0 {
			str += "*"
		}
	*/
	if *m&MsgRecReplF != 0 {
		str += strconv.Itoa(int(*m & MsgRecStatusMask))
	} else {
		str += sipsp.SIPMethod(*m & MsgRecMethodMask).String()
	}
	if *m&MsgRecRetrMask != 0 {
		str += "{" +
			strconv.Itoa(int(uint(*m&MsgRecRetrMask)>>MsgRecRetrPos)) + "}"
	}
	return str
}

// records a message "backtrace" (method type/repl status, direction, isRetr)
// TODO: move it in a separate file and conditional compile
type MsgBackTrace struct {
	Msgs [16]MsgRec
	N    uint // number of message
}

func (m *MsgBackTrace) AddReq(method sipsp.SIPMethod, dir, retr int) {
	if retr != 0 && m.N > 0 {
		var mr MsgRec
		mr.InitReq(method, dir, 0)
		idx := int(m.N-1) % len(m.Msgs)
		if m.Msgs[idx]&^MsgRecRetrMask == mr && m.Msgs[idx].Retrs() > 0 {
			newRetr := m.Msgs[idx].Retrs() + retr
			if newRetr > MsgRecMaxRetr {
				retr -= (newRetr - MsgRecMaxRetr)
				newRetr = MsgRecMaxRetr
				m.Msgs[idx].SetRetrs(newRetr)
				// fallthrough to adding new "record" with rest retrs.
			} else {
				// update existing record and exit
				m.Msgs[idx].SetRetrs(newRetr)
				return
			}
		}
	}
	m.Msgs[int(m.N)%len(m.Msgs)].InitReq(method, dir, retr)
	m.N++
}

func (m *MsgBackTrace) AddRepl(status uint16, dir, retr int) {
	if retr != 0 && m.N > 0 {
		var mr MsgRec
		mr.InitRepl(status, dir, 0)
		idx := int(m.N-1) % len(m.Msgs)
		if m.Msgs[idx]&^MsgRecRetrMask == mr && m.Msgs[idx].Retrs() > 0 {
			newRetr := m.Msgs[idx].Retrs() + retr
			if newRetr > MsgRecMaxRetr {
				retr -= (newRetr - MsgRecMaxRetr)
				newRetr = MsgRecMaxRetr
				m.Msgs[idx].SetRetrs(newRetr)
				// fallthrough to adding new "record" with rest retrs.
			} else {
				// update existing record and exit
				m.Msgs[idx].SetRetrs(newRetr)
				return
			}
		}
	}
	m.Msgs[int(m.N)%len(m.Msgs)].InitRepl(status, dir, retr)
	m.N++
}

func (m *MsgBackTrace) String() string {
	var i uint
	var str string
	// last len(Msgs) entries
	if m.N > uint(len(m.Msgs)) {
		i = m.N - uint(len(m.Msgs))
		// missing messages
		str = "...[" + strconv.Itoa(int(i)) + "]"
	}
	for ; i != m.N; i++ {
		/*
			if str != "" {
				str += ","
			}
		*/
		str += m.Msgs[int(i)%len(m.Msgs)].String()
	}
	return str
}

// debugging received msg "backtrace"
// TODO: move it in a separate file and conditional compile
type StateBackTrace struct {
	PrevState [10]CallState // last 10 states
	N         uint          // number of state transitions
}

func (s *StateBackTrace) Add(cs CallState) {
	s.PrevState[int(s.N)%len(s.PrevState)] = cs
	s.N++
}

func (s *StateBackTrace) String() string {
	var i uint
	var str string
	// last len(prevState) entries
	if s.N > uint(len(s.PrevState)) {
		i = s.N - uint(len(s.PrevState))
		// missing messages
		str = "...[" + strconv.Itoa(int(i)) + "]"
	}
	for ; i != s.N; i++ {
		if str != "" {
			str += "->"
		}
		str += s.PrevState[int(i)%len(s.PrevState)].String()
	}
	return str
}

// CallEntry holds dialog or call state information in a compact form.
// WARNING: since a custom mem. allocator will be used in the future, do
//          not use pointers to go allocated objects (or GC might delete
//          them)
type CallEntry struct {
	next, prev *CallEntry
	Key        CallKey
	CSeq       [2]uint32
	ReplCSeq   [2]uint32
	ReqsNo     [2]uint
	ReplsNo    [2]uint
	ReplStatus [2]uint16
	hashNo     uint32          // cache hash value
	Method     sipsp.SIPMethod // creating method
	Flags      CallFlags
	State      CallState
	EvFlags    EventFlags // sent/generated events
	evHandler  HandleEvF  // event handler function

	// used only for REGISTERS:
	regBinding *RegEntry // pointer to cached registry binding

	// TODO: replace all time.Time with uint64 (time.Time is too big and
	//       has a time zone _pointer_ inside causing extra uneeded GC work)
	StartTS        time.Time // call established time
	CreatedTS      time.Time // debugging
	forkedTS       time.Time // debugging
	ReqsRetrNo     [2]uint
	ReplsRetrNo    [2]uint
	lastMethod     [2]sipsp.SIPMethod // last non-retr. method  in the "dialog"
	lastReplStatus [2]uint16          // last non-retry. reply status seen
	prevState      StateBackTrace     // debugging
	lastMsgs       MsgBackTrace       // debugging
	lastEv         EventType          // debugging: event before crtEv
	crtEv          EventType          // debugging: most current event
	evGen          EvGenPos           // debugging

	Timer  TimerInfo
	refCnt int32 // reference counter, atomic

	EndPoint [2]NetInfo
	Info     CallInfo
}

// Reset the CallEntry structure, keeping the internal buffers (key.buf)
func (c *CallEntry) Reset() {
	buf := c.Key.buf
	buf2 := c.Info.buf
	*c = CallEntry{}
	c.Key.buf = buf
	c.Info.buf = buf2[0:0]
}

/*
func (c *CallEntry) Hash() uint32 {
	if c.Flags&CFHashed == 0 {
		c.hashNo = GetHash(c.Key.buf, int(c.Key.CallID.Offs), int(c.Key.CallID.Len))
		c.Flags |= CFHashed
	}
	return c.hashNo
}
*/

// Ref increased the internal reference counter. Returns the new value.
func (c *CallEntry) Ref() int32 {
	return atomic.AddInt32(&c.refCnt, 1)
}

// Unref decrements the reference counter and if 0 frees the CallEntry.
// Returns true if the CallEntry was freed and false if it's still referenced
func (c *CallEntry) Unref() bool {
	if atomic.AddInt32(&c.refCnt, -1) == 0 {
		// sanity regBinding check
		if c.regBinding != nil {
			// NOTE: if refCnt is 0 then c.regBinding should be always nil
			// otherwise c should be still ref'ed from the reg cache entry
			// and the refCnt would not be 0
			BUG("CallEntry.Unref(): 0 refCnt but still linked "+
				"from regBinding cache: %p <- %p [%v]\n",
				c, c.regBinding, *c.regBinding)
			// Failsafe: even in the "buggy" case attempt to "recover"
			// lock, & try to remove regBinding
			locked := lockRegEntry(c.regBinding)
			c.regBinding.ce = nil
			if locked {
				unlockRegEntry(c.regBinding)
			}
			c.regBinding.Unref()
		}
		FreeCallEntry(c)
		return true
	}
	return false
}

// match returns the "matching type" between the current call entry and
// a callid, fromtag and totag extracted from a message.
// If it matches in the reverse direction (e.g. msg. from callee, call entry
// created based on caller message) the returned dir will be 1.
func (c *CallEntry) match(callid, fromtag, totag []byte) (m CallMatchType, dir int) {
	m = CallNoMatch
	dir = 0
	if (int(c.Key.CallID.Len) != len(callid)) ||
		!bytes.Equal(c.Key.GetCallID(), callid) {
		return
	}
	m = CallCallIDMatch
	if (int(c.Key.FromTag.Len) == len(fromtag)) &&
		bytes.Equal(c.Key.GetFromTag(), fromtag) {
		m = CallPartialMatch
		dir = 0
		// check if full match
		if (int(c.Key.ToTag.Len) == len(totag)) &&
			bytes.Equal(c.Key.GetToTag(), totag) {
			m = CallFullMatch
		}
	} else if (int(c.Key.FromTag.Len) == len(totag)) &&
		bytes.Equal(c.Key.GetFromTag(), totag) {
		// no from tag match, but from tag == msg to tag
		// => reverse direction
		dir = 1
		m = CallPartialMatch
		if (int(c.Key.ToTag.Len) == len(fromtag)) &&
			bytes.Equal(c.Key.GetToTag(), fromtag) {
			m = CallFullMatch
		}
	}
	return
}

type CallMatchType uint8

const (
	CallErrMatch CallMatchType = iota + 1 // error, e.g.: invalid message
	CallNoMatch
	CallCallIDMatch  // only CallID  matched
	CallPartialMatch // CallID
	CallFullMatch
)

type NetInfo struct {
	Port   uint16
	Flags  NAddrFlags // address family | proto | ...
	IPAddr [16]byte   // holds IPv4 or IPv6, type in Flags
}

type NAddrFlags uint8

const (
	NProtoUDP NAddrFlags = 1 << iota
	NProtoTCP
	NProtoSCTP
	NProtoTLS
	NProtoDTLS
	NAddrIPv6
)

const NProtoMask = NProtoUDP | NProtoTCP | NProtoSCTP | NProtoTLS | NProtoDTLS

var protoNames = [...]string{
	"udp",
	"tcp",
	"sctp",
	"tls",
	"dtls",
}

func (f NAddrFlags) Proto() NAddrFlags {
	return f & NProtoMask
}

func (f NAddrFlags) ProtoName() string {
	for i, v := range protoNames {
		if f&(1<<uint(i)) != 0 {
			return v
		}
	}
	return ""
}

func (n *NetInfo) Reset() {
	*n = NetInfo{}
}

func (n *NetInfo) IP() net.IP {
	if n.Flags&NAddrIPv6 != 0 {
		return net.IP(n.IPAddr[:])
	}
	return net.IP(n.IPAddr[:4])
}

func (n *NetInfo) SetIP(ip *net.IP) {
	if len(*ip) == 16 {
		n.SetIPv6([]byte(*ip))
	}
	n.SetIPv4([]byte(*ip))
}

func (n *NetInfo) SetIPv4(ip []byte) {
	copy(n.IPAddr[:], ip[:4])
	n.Flags &^= NAddrIPv6
}

func (n *NetInfo) SetIPv6(ip []byte) {
	copy(n.IPAddr[:], ip[:16])
	n.Flags |= NAddrIPv6
}

func (n *NetInfo) SetProto(p NAddrFlags) bool {
	if p&NProtoMask != 0 {
		n.Flags |= p
		return true
	}
	return false
}

func (n *NetInfo) Proto() NAddrFlags {
	return n.Flags.Proto()
}

func (n *NetInfo) ProtoName() string {
	return n.Flags.ProtoName()
}
