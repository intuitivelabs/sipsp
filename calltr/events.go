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
	EvBad
)

var evTypeName = [...]string{
	EvNone:        "",
	EvCallStart:   "call-start",
	EvCallEnd:     "call-end",
	EvCallAttempt: "call-attempt",
	EvAuthFailed:  "auth-failed",
	EvActionLog:   "action-log",
	EvBad:         "invalid",
}

func (e EventType) String() string {
	if int(e) >= len(evTypeName) {
		e = EvBad
	}
	return evTypeName[int(e)]
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
	to-ua
	xcallid
	from
	to
	x-org-connid
	*/
}
