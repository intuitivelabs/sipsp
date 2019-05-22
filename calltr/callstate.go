package calltr

import (
	"bytes"
	"net"
	// "sync"
	"sync/atomic"

	"andrei/sipsp"
)

const (
	ToTagMinSpace   = 8   // minimum space reserver for to-tag
	MaxTagSpace     = 384 // maximum space reserved for callid + fromtag + totag
	HashSize        = 65536
	DefaultToTagLen = 50 // space reserved for totag
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
	maxl := cap(c.buf)
	callidLen := len(callid)
	fromtagLen := len(fromtag)
	if callidLen+fromtagLen+reserve > maxl {
		DBG("SetCF(l:%d, l:%d, %d) failed max len %d\n",
			callidLen, fromtagLen, reserve, maxl)
		return false
	}
	copy(c.buf[:], callid)
	c.CallID.Set(0, callidLen)
	copy(c.buf[callidLen:], fromtag)
	c.FromTag.Set(callidLen, callidLen+fromtagLen)
	c.ToTag.Set(callidLen+fromtagLen, callidLen+fromtagLen)
	return true
}

// TagSpace returns true if there is enough space for a from tag and a
// to tag of the given lengths. It assumes the callid was already set.
func (c *CallKey) TagSpace(fTagLen, tTagLen int) bool {
	fTagOffs := (int)(c.CallID.Offs + c.CallID.Len)
	maxl := cap(c.buf) - fTagOffs
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
	if c.TagSpace(newFTagLen, reserve) == false {
		return false
	}
	copy(c.buf[fTagOffs:], fromtag)
	c.FromTag.Set(fTagOffs, newFTagLen)
	c.ToTag.Set(fTagOffs+newFTagLen, fTagOffs+newFTagLen)
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
	maxl := cap(c.buf)
	callidLen := int(c.CallID.Len)
	fromtagLen := int(c.FromTag.Len)
	totagLen := len(totag)
	if callidLen == 0 || fromtagLen == 0 {
		return false
	}
	if callidLen+fromtagLen+totagLen > maxl {
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
	CFHashed CallFlags = 1 << iota
)

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

	EndPoint [2]NetInfo

	Timer  TimerInfo
	refCnt int32 // reference counter, atomic
}

// Reset the CallEntry structure, keeping the internal buffers (key.buf)
func (c *CallEntry) Reset() {
	buf := c.Key.buf
	*c = CallEntry{}
	c.Key.buf = buf
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
	NAddrIPv6
)

func (n *NetInfo) Reset() {
	*n = NetInfo{}
}

func (n *NetInfo) IP() net.IP {
	if n.Flags&NAddrIPv6 != 0 {
		return net.IP(n.IPAddr[:])
	}
	return net.IP(n.IPAddr[:4])
}

func (n *NetInfo) SetIP(ip net.IP) {
	if len(ip) == 16 {
		n.SetIPv6([]byte(ip))
	}
	n.SetIPv4([]byte(ip))
}

func (n *NetInfo) SetIPv4(ip []byte) {
	copy(n.IPAddr[:], ip[:4])
	n.Flags &^= NAddrIPv6
}

func (n *NetInfo) SetIPv6(ip []byte) {
	copy(n.IPAddr[:], ip[:16])
	n.Flags |= NAddrIPv6
}
