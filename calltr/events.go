package calltr

import (
	"fmt"
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
	EvNone:        "empty",
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

type EventFlags uint16

// returns previous value
func (f *EventFlags) Set(e EventType) bool {
	m := uint(1) << uint(e)
	ret := (uint(*f) & m) != 0
	*f = EventFlags(uint(*f) | m)
	return ret
}

// returns previous value
func (f *EventFlags) Clear(e EventType) bool {
	m := uint(1) << uint(e)
	ret := (uint(*f) & m) != 0
	*f = EventFlags(uint(*f) &^ m)
	return ret
}

func (f *EventFlags) Test(events ...EventType) bool {
	for _, e := range events {
		if uint(*f)&(1<<uint(e)) != 0 {
			return true
		}
	}
	return false
}

func (f *EventFlags) ResetAll() {
	*f = 0
}

func (f *EventFlags) String() string {
	var s string
	for e := EvNone + 1; e < EvBad; e++ {
		if f.Test(e) {
			if s != "" {
				s += "|" + e.String()
			} else {
				s += e.String()
			}
		}
	}
	return s
}

// maximum size of an event data buffer
func EventDataMaxBuf() int {
	s := MaxTagSpace + 16 /* SrcIP */ + 16 /* DstIP */
	for i := 0; i < int(AttrLast); i++ {
		m := int(AttrSpace[i].Max)
		if m > 0 {
			s += m
		}
	}
	return s
}

type EvGenPos uint8 // debugging
const (
	EvGenUnknown EvGenPos = iota
	EvGenReq
	EvGenRepl
	EvGenTimeout
)

func (p EvGenPos) String() string {
	switch p {
	case EvGenReq:
		return "request"
	case EvGenRepl:
		return "reply"
	case EvGenTimeout:
		return "timeout"
	}
	return "unknown"
}

type EventData struct {
	Type       EventType
	Truncated  bool
	TS         time.Time // event creation time
	CreatedTS  time.Time // call entry creation
	StartTS    time.Time // call start
	Src        net.IP
	Dst        net.IP
	SPort      uint16
	DPort      uint16
	ProtoF     NAddrFlags
	ReplStatus uint16
	CallID     sipsp.PField
	Attrs      [AttrLast]sipsp.PField

	// debugging
	ForkedTS   time.Time
	State      CallState
	PrevState  StateBackTrace
	LastMethod [2]sipsp.SIPMethod
	LastStatus [2]uint16
	LastEv     EventType
	EvFlags    EventFlags
	CFlags     CallFlags
	CSeq       [2]uint32
	RCSeq      [2]uint32
	Reqs       [2]uint
	Repls      [2]uint
	ReqsRetr   [2]uint
	ReplsRetr  [2]uint
	LastMsgs   MsgBackTrace
	FromTag    sipsp.PField
	ToTag      sipsp.PField
	EvGen      EvGenPos // where was the event generated

	Valid int    // no of valid, non truncated PFields
	Used  int    // how much of the buffer is used / current offset
	Buf   []byte // buffer where all the content is saved
}

func (ed *EventData) Reset() {
	buf := ed.Buf
	*ed = EventData{}
	ed.Buf = buf
}

func (ed *EventData) Init(buf []byte) {
	ed.Reset()
	ed.Buf = buf
}

// quick copy hack when there is enough space
func (ed *EventData) Copy(src *EventData) bool {
	if len(ed.Buf) < src.Used {
		// not enough space
		return false
	}
	buf := ed.Buf
	*ed = *src
	ed.Buf = buf
	copy(ed.Buf, src.Buf[:src.Used])
	return true
}

var fakeCancelReason = []byte("internal: cancel")
var fakeTimeoutReason = []byte("internal: call state timeout")
var fake2xxReason = []byte("internal: implied OK")

// Fill EventData from a CallEntry.
// Returns the number of PFields added. For a valid event, at least 1.
func (d *EventData) Fill(ev EventType, e *CallEntry) int {
	var forcedReason []byte
	d.Type = ev
	d.Truncated = false
	d.TS = time.Now()
	d.CreatedTS = e.CreatedTS
	d.StartTS = e.StartTS
	d.ProtoF = e.EndPoint[0].Proto()
	ip := e.EndPoint[0].IP()
	n := copy(d.Buf[d.Used:], ip)
	d.Src = d.Buf[d.Used : d.Used+n]
	d.Used += n
	if n < len(ip) {
		d.Truncated = true
		return d.Valid
	}
	ip = e.EndPoint[1].IP()
	n = copy(d.Buf[d.Used:], ip)
	d.Dst = d.Buf[d.Used : d.Used+n]
	d.Used += n
	if n < len(ip) {
		d.Truncated = true
		return d.Valid
	}
	d.SPort = e.EndPoint[0].Port
	d.DPort = e.EndPoint[1].Port
	d.ReplStatus = e.ReplStatus[0]
	// fix ReplStatus
	if d.ReplStatus < 200 {
		if e.Flags&CFTimeout != 0 {
			// if call entry did timeout start with a fake 408
			d.ReplStatus = 408
			forcedReason = fakeTimeoutReason
		}
		switch ev {
		case EvCallStart:
			// call reconstructed due to in-dialog method
			d.ReplStatus = 290
			forcedReason = fake2xxReason
		case EvCallAttempt:
			switch e.State {
			case CallStCanceled:
				d.ReplStatus = 487 // fake 487
				forcedReason = fakeCancelReason
			default:
			}
		case EvCallEnd:
			d.ReplStatus = 291
			forcedReason = fake2xxReason
		}
	}

	//debug stuff
	d.ForkedTS = e.forkedTS
	d.State = e.State
	d.PrevState = e.prevState
	d.LastMethod = e.lastMethod
	d.LastStatus = e.lastReplStatus
	d.LastEv = e.lastEv
	d.EvFlags = e.EvFlags
	d.CFlags = e.Flags
	d.EvGen = e.evGen
	d.CSeq = e.CSeq
	d.RCSeq = e.ReplCSeq
	d.Reqs = e.ReqsNo
	d.Repls = e.ReplsNo
	d.ReqsRetr = e.ReqsRetrNo
	d.ReplsRetr = e.ReplsRetrNo
	d.LastMsgs = e.lastMsgs
	// end of debug

	n = addPField(&e.Key.CallID, e.Key.buf,
		&d.CallID, &d.Buf, &d.Used, -1)
	if n < int(e.Key.CallID.Len) {
		d.Truncated = true
		return d.Valid
	}
	d.Valid++
	// add Reason "by-hand"
	if forcedReason != nil {
		n = addSlice(forcedReason,
			&d.Attrs[AttrReason], &d.Buf, &d.Used, -1)
		if n < len(forcedReason) {
			d.Truncated = true
			return d.Valid
		}
	} else {
		n = addPField(&e.Info.Attrs[AttrReason], e.Info.buf,
			&d.Attrs[AttrReason], &d.Buf, &d.Used, -1)
		if n != int(e.Info.Attrs[AttrReason].Len) {
			d.Truncated = true
			return d.Valid
		}
	}
	d.Valid++
	for i := 0; i < len(d.Attrs); i++ {
		if CallAttrIdx(i) == AttrReason {
			continue // skip, Reason handled above
		}
		n = addPField(&e.Info.Attrs[i], e.Info.buf,
			&d.Attrs[i], &d.Buf, &d.Used, -1)
		if n != int(e.Info.Attrs[i].Len) {
			d.Truncated = true
			break
		}
		d.Valid++
	}
	// more debug stuff
	n = addPField(&e.Key.FromTag, e.Key.buf,
		&d.FromTag, &d.Buf, &d.Used, -1)
	if n < int(e.Key.FromTag.Len) {
		d.Truncated = true
		return d.Valid
	}
	n = addPField(&e.Key.ToTag, e.Key.buf,
		&d.ToTag, &d.Buf, &d.Used, -1)
	if n < int(e.Key.ToTag.Len) {
		d.Truncated = true
		return d.Valid
	}
	return d.Valid
}

/*
// Fill EventData from a RegEntry. Only valid for evRegExpired for now.
// Returns the number of PFields added. For a valid event, at least 1.
func (d *EventData) FillFromRegEntry(ev EventType, e *RegEntry) int {
	var forcedReason []byte
	d.Type = ev
	d.Truncated = false
	d.TS = time.Now()
	d.CreatedTS = e.CreatedTS
	d.StartTS = e.CreatedTS // for a RegEntry these are the same
	d.ProtoF = e.EndPoint[0].Proto()
	ip := e.EndPoint[0].IP()
	n := copy(d.Buf[d.Used:], ip)
	d.Src = d.Buf[d.Used : d.Used+n]
	d.Used += n
	if n < len(ip) {
		d.Truncated = true
		return d.Valid
	}
	ip = e.EndPoint[1].IP()
	n = copy(d.Buf[d.Used:], ip)
	d.Dst = d.Buf[d.Used : d.Used+n]
	d.Used += n
	if n < len(ip) {
		d.Truncated = true
		return d.Valid
	}
	d.SPort = e.EndPoint[0].Port
	d.DPort = e.EndPoint[1].Port
	switch ev {
	case EvRegExpired:
		d.ReplStatus = 408
		forcedReason = fakeTimeoutReason
	case EvRegDel, EvRegNew:
		// the event should be directly generated fron the Register reply
		// and Fill-ed from the CallEntry, not from here
		// (whe don't have all the information)
		// However if called, try to fake something
		d.ReplStatus = 292
		forcedReason = fake2xxReason
	default:
		// should never reach this point
		d.ReplStatus = 699
	}


	// add Reason "by-hand"
	if forcedReason != nil {
		n = addSlice(forcedReason,
			&d.Attrs[AttrReason], &d.Buf, &d.Used, -1)
		if n < len(forcedReason) {
			d.Truncated = true
			return d.Valid
		}
	}
	d.Valid++

	n = addPField(&e.AOR, e.buf, &d.Attrs[AttrFromURI], &d.Buf,
		&d.Used, -1)
	if n != int(e.AOR.Len) {
		d.Truncated = true
		return d.Valid
	}
	d.Valid++
	n = addPField(&e.AOR, e.buf, &d.Attrs[AttrToURI], &d.Buf,
		&d.Used, -1)
	if n != int(e.AOR.Len) {
		d.Truncated = true
		return d.Valid
	}
	d.Valid++

	return d.Valid
}
*/

// mostly for debugging
func (ed *EventData) String() string {
	var duration time.Duration
	if !ed.StartTS.IsZero() {
		duration = ed.TS.Sub(ed.StartTS)
	}
	s := fmt.Sprintf(
		"Type: %s [truncated: %v valid fields: %2d used: %5d/%5d]\n"+
			"	ts        : %s\n"+
			"	created   : %s (%s ago)\n"+
			"	call-start: %s duration: %s \n"+
			"	protocol  : %s  %s:%d -> %s:%d\n"+
			"	sip.call_id: %s\n"+
			"	sip.response.status: %3d\n",
		ed.Type, ed.Truncated, ed.Valid, ed.Used, cap(ed.Buf),
		ed.TS.Truncate(time.Second),
		ed.CreatedTS.Truncate(time.Second),
		time.Now().Sub(ed.CreatedTS).Truncate(time.Second),
		ed.StartTS.Truncate(time.Second),
		duration,
		ed.ProtoF.ProtoName(), ed.Src, ed.SPort, ed.Dst, ed.DPort,
		ed.CallID.Get(ed.Buf),
		ed.ReplStatus)
	for i := 0; i < len(ed.Attrs); i++ {
		if !ed.Attrs[i].Empty() {
			s += fmt.Sprintf("	%s: %q\n",
				CallAttrIdx(i), ed.Attrs[i].Get(ed.Buf))
		}
	}
	s += fmt.Sprintf("	DBG: state: %q  pstate: %q\n", ed.State, ed.PrevState.String())
	s += fmt.Sprintf("	DBG: fromTag: %q toTag: %q\n",
		ed.FromTag.Get(ed.Buf), ed.ToTag.Get(ed.Buf))
	s += fmt.Sprintf("	DBG:  lastev: %q evF: %s (%2X) generated on: %s\n",
		ed.LastEv, ed.EvFlags.String(), ed.EvFlags, ed.EvGen.String())
	s += fmt.Sprintf("	DBG: cseq: %6d/%6d  rcseq: %6d/%6d forked: %s\n",
		ed.CSeq[0], ed.CSeq[1], ed.RCSeq[0], ed.RCSeq[1], ed.ForkedTS)
	s += fmt.Sprintf("	DBG: reqNo: %4d/%4d retr: %4d/%4d"+
		" replNo: %4d/%4d retr: %4d/%4d\n",
		ed.Reqs[0], ed.Reqs[1], ed.ReqsRetr[0], ed.ReqsRetr[1],
		ed.Repls[0], ed.Repls[1],
		ed.ReplsRetr[0], ed.ReplsRetr[1])
	s += fmt.Sprintf("	DBG: call flags: %s (0x%02x)\n",
		ed.CFlags, int(ed.CFlags))
	s += fmt.Sprintf("	DBG: last method: %v  last status:%v\n",
		ed.LastMethod, ed.LastStatus)
	s += fmt.Sprintf("	DBG: msg trace: %s\n", ed.LastMsgs.String())
	return s
}

// HandleEvF is a function callback that should handle a new CallEvent.
// It should copy all the needed information from the passed CallEvent
// structure, since the date _will_ be overwritten after the call
// (so all the []byte slices _must_ be copied if needed).
type HandleEvF func(callev *EventData)

// update "event state", catching already generated events
// returns ev or EvNone (if event was a retr)
// unsafe, MUST be called w/ _e_ lock held or if no parallel access is possible
func updateEvent(ev EventType, e *CallEntry) EventType {
	// new event only if entry was not already canceled and event not
	// already generated
	if ev != EvNone && (e.Flags&CFCanceled == 0) && !e.EvFlags.Set(ev) {
		// event not seen before
		switch ev {
		case EvCallStart, EvRegNew, EvSubNew:
			e.StartTS = time.Now()
		case EvCallAttempt:
			// report call attempts only once per call and not per each
			//  branch and only if no EvCallStart or EvCallEnd seen.
			if e.Flags&(CFForkChild|CFForkParent) != 0 {
				f := cstHash.HTable[e.hashNo].SetAllRelatedEvFlag(e, ev)
				if f.Test(EvCallAttempt, EvCallStart, EvCallEnd) {
					return EvNone
				}
			}
		}
		e.lastEv, e.crtEv = e.crtEv, ev // debugging
		return ev
	}
	return EvNone
}

/*
// unsafe, should be called either under lock or when is guaranteed that
// no one can use the call entry in the same time.
func generateEvent(ev EventType, e *CallEntry, f HandleEvF) bool {
	if e.EvFlags.Test(ev) {
		// already generated
		return false
	}
	e.EvFlags.Set(ev)
	if f != nil {
		var callev EventData
		var buf = make([]byte, EventDataMaxBuf())
		callev.Init(buf)
		callev.Fill(ev, e)
		f(&callev)
	}
	return true
}
*/
