package calltr

import (
	"net"
	"time"

	"andrei/sipsp"
)

type EventType uint8

const (
	EvNone EventType = iota
	EvCallStart
	EvCallEnd
	EvCallAttempt
	EvAuthFailed
	EvActionLog
	EvRegNew
	EvRegDel
	EvRegExpired
	EvSubNew
	EvSubDel
	EvBad
)

var evTypeName = [EvBad + 1]string{
	EvNone:        "",
	EvCallStart:   "call-start",
	EvCallEnd:     "call-end",
	EvCallAttempt: "call-attempt",
	EvAuthFailed:  "auth-failed",
	EvActionLog:   "action-log",
	EvRegNew:      "reg-new",
	EvRegDel:      "reg-del",
	EvRegExpired:  "reg-expired",
	EvSubNew:      "sub-new",
	EvSubDel:      "sub-del",
	EvBad:         "invalid",
}

func (e EventType) String() string {
	if int(e) >= len(evTypeName) {
		e = EvBad
	}
	return evTypeName[int(e)]
}

type EventFlags uint8

// returns previous value
func (f *EventFlags) Set(e EventType) bool {
	m := uint(1) << uint(e)
	ret := (uint(*f) & m) != 0
	*f = EventFlags(uint(*f) | m)
	return ret
}

func (f *EventFlags) Test(e EventType) bool {
	return uint(*f)&(1<<uint(e)) != 0
}

func (f *EventFlags) ResetAll() {
	*f = 0
}

type CallEvent struct {
	Type  EventType
	Ts    time.Time
	Attrs CallAttrs
}

type CallAttrs struct {
	CallID    []byte
	From      []byte // uri ? not supported
	To        []byte // uri ? not supported
	SipCode   uint16 // reply status code
	Method    sipsp.SIPMethod
	Transport []byte // text form?
	Source    net.IP
	// ? Dest?
	SrcPort uint16
	/* extra headers/msg info:
	r-uri
	from-ua
	from  - uri
	to    - uri
	contact
	*/
	/* ignored
	to-ua
	xcallid
	x-org-connid
	*/
}

func fillCallEv(ev EventType, e *CallEntry, callev *CallEvent) {
	callev.Type = ev
	callev.Ts = time.Now()
	callev.Attrs.CallID = e.Key.GetCallID()
	callev.Attrs.SipCode = e.ReplStatus[0]
	callev.Attrs.Method = e.Method
	// TODO: ....
}

// HandleEvF is a function callback that should handle a new CallEvent.
// It should copy all the needed information from the passed CallEvent
// structure, since the date _will_ be overwritten after the call
// (so all the []byte slices _must_ be copied if needed).
type HandleEvF func(callev *CallEvent)

// unsafe, should be called either under lock or when is guaranteed that
// no one can use the call entry in the same time.
func generateEvent(ev EventType, e *CallEntry, f HandleEvF) bool {
	if e.EvFlags.Test(ev) {
		// already generated
		return false
	}
	e.EvFlags.Set(ev)
	if f != nil {
		var callev CallEvent
		fillCallEv(ev, e, &callev)
		f(&callev)
	}
	return true
}
