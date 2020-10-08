package regtr

// registration tracker

import (
	"sync/atomic"
	"time"

	"github.com/intuitivelabs/sipsp"
	"github.com/intuitivelabs/sipsp/calltr"
)

type Binding struct {
	aorNext, aorPrev *Binding // link into AOR hash
	//cNext, cPrev     *Binding // linnk into Contact hash
	AOR        sipsp.PField
	Contact    sipsp.PField
	CallID     sipsp.PField
	AORURI     sipsp.PsipURI
	ContactURI sipsp.PsipURI
	CSeq       uint32
	Q          uint16
	Expire     uint32

	hashNoAor     uint32
	hashNoContact uint32

	StartTS   time.Time
	CreatedTS time.Time

	Timer  calltr.TimerInfo
	refCnt int32

	EndPoint [2]calltr.NetInfo
	// AOR, Contact, CallID are stored inside the CallInfo buffer
	// (Info.buf & Info.used)
	Info CallInfo // various attrs pfields + buffer for storing them
}

func (b *Binding) Reset() {
	buf := b.Info.buf
	*b = Binding{}
	b.Info.Init(buf)
}

func (b *Binding) Init(buf []byte) {
	b.Reset()
	b.Info.Init(buf)
}

func (b *Binding) Ref() int32 {
	return atomic.AddInt32(&b.refCnt, 1)
}

func (b *Binding) Unref() bool {
	if atomic.AddInt32(&b.refCnt, -1) == 0 {
		FreeBinding(b)
		return true
	}
	return false
}

func (b *Binding) MatchAOR(aorURI *sipsp.PsipURI, buf []byte) bool {
	return sipsp.URICmpShort(&b.AORURI, b.Info.buf, aorURI, buf)
}

func (b *Binding) MatchContact(cURI *sipsp.PsipURI, buf []byte) bool {
	// TODO: treat escape; full cmp including params & headers
	return sipsp.URICmpShort(&b.ContactURI, b.Info.buf, cURI, buf)
}

func (b *Binding) addPField(f sipsp.PField, buf []byte) (sipsp.PField, bool) {
	var r sipsp.PField
	maxl := len(b.buf) - b.pos
	if int(f.Len) > maxl {
		return r, false
	}
	addPField(&f, buf, &r, &b.Info.buf, &b.Info.used, 0)
	return r, true
}

func (b *Binding) SetAORURI(aorURI sipsp.PsipURI, buf []byte) bool {
	var ok bool
	aor := aorURI.Shortened()
	if b.AOR, ok = b.addPField(aor, buf); !ok {
		return false
	}
	b.AORURI = aorURI
	b.AORURI.Truncate()
	if !b.AORURI.AdjustOffs(b.AOR) {
		// undo changes
		b.pos -= int(b.AOR.Len)
		b.AOR.Reset()
		b.AORURI.Reset()
		return false
	}
	return true
}

func (b *Binding) SetContactURI(cURI sipsp.PsipURI, buf []byte) bool {
	var ok bool
	// TODO PsipURI.Get(Buf) ....
	contact := cURI.Shortened() // TODO: should be the whole URI
	if b.Contact, ok = b.addPField(contact, buf); !ok {
		return false
	}
	b.ContactURI = cURI
	b.ContactURI.Truncate() // TODO: should be the whole URI!
	if !b.ContactURI.AdjustOffs(b.Contact) {
		// undo changes
		b.pos -= int(b.Contact.Len)
		b.Contact.Reset()
		b.ContactURI.Reset()
		return false
	}
	return true
}

func (b *Binding) SetCallID(cid sipsp.PField, buf []byte) bool {
	var ok bool
	b.CallID, ok = b.addPField(cid, buf)
	return ok
}
