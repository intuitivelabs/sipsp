package calltr

import (
	"andrei/sipsp"
)

// return true if this looks like a request retr.
func reqRetr(e *CallEntry, m *sipsp.PSIPMsg, dir int) bool {
	mcseq := m.PV.CSeq.CSeqNo
	mmethod := m.FL.MethodNo
	if mcseq < e.CSeq[dir] ||
		(mcseq == e.CSeq[dir] &&
			mmethod != sipsp.MAck && mmethod != sipsp.MCancel) {
		return true
	}
	return false
}

// return true if the status code s is a 2xx
func is2xx(s uint16) bool {
	return (s <= 299) && (s >= 200)
}

func authFailure(s uint16) bool {
	return (s == 401) || (s == 407)
}

// return true if this looks like a reply retr.
func replRetr(e *CallEntry, m *sipsp.PSIPMsg, dir int) bool {
	mstatus := m.FL.Status
	mcseq := m.PV.CSeq.CSeqNo
	if mcseq < e.CSeq[dir] || mcseq < e.ReplCSeq[dir] ||
		(mcseq == e.ReplCSeq[dir] &&
			mstatus <= e.ReplStatus[dir] &&
			(!is2xx(mstatus) || is2xx(e.ReplStatus[dir]))) {
		return true
	}
	return false
}

// updateStateReq() updates the call state in a forgiving maximum compatibility
// mode (it will try to recover from skipped messages), for a given request
// message.
// It uses the message method, cseq, presence/absence of the totag and the
// "direction" of the message to check for retransmissions (which will not
// cause a state change).
// dir is the direction of the "transaction initiator": it's 0 for requests
// from the caller and  replies from the callee (totag matches exactly) and
// 1 for requests from the callee and replies from the caller (totag matches
// fromtag).
// See also updateStateRepl().
// It returns the cuurent, updtead CallState and a EventType
// The EventType is not checked for uniqueness (e.g. several call-start could
// be generated one-after-another if several 2xx arrive)
func updateStateReq(e *CallEntry, m *sipsp.PSIPMsg, dir int) (CallState, EventType) {
	mmethod := m.FL.MethodNo
	mcseq := m.PV.CSeq.CSeqNo
	mhastotag := !m.PV.To.Tag.Empty()
	prevState := e.State
	newState := CallStNone
	event := EvNone
	if reqRetr(e, m, dir) ||
		mmethod == sipsp.MPrack /* ignore PRACKs */ ||
		mmethod == sipsp.MUpdate /* ignore UPDATEs */ {
		// retransmission
		goto retr
	}
	switch mmethod {
	case sipsp.MBye:
		newState = CallStBye
		event = EvCallEnd // for extra reliability: both on BYE and BYE repl.
	case sipsp.MCancel:
		switch prevState {
		case CallStInit, CallStFInv, CallStEarlyDlg:
			// not 100% conformant, but more "compatible" with broken UAs
			newState = CallStCanceled
			event = EvCallAttempt
		default:
			newState = prevState // ignore CANCEL, keep old state
		}
	default:
		// INVITE, ACK or non-INVITE in-dialog
		if mhastotag {
			switch prevState {
			case CallStInit:
				switch mmethod {
				case sipsp.MInvite:
					// missed first invite
					newState = CallStEstablished
					event = EvCallStart
				case sipsp.MAck:
					// we don't know the ACK type
					newState = prevState // keep state for ack
				default:
					newState = CallStFNonInv
				}
			case CallStFInv, CallStEarlyDlg:
				// reply missed somehow, recover...
				newState = CallStEstablished
				event = EvCallStart
			default:
				newState = prevState // keep same state
			}
			goto end
		} // else
		/* no To tag and no retransmission => it's one of the following
		cases:
		 - start of a new dialog if CallStInit
		 - retry a request after a negative reply (CallStNegReply or
		 CallStNonInvNegReply)
		 -  like above, but a request for which we missed the negative
		 reply
		 - some strange broken call
		*/
		/* we allow for missed replies, if not execute the following
		code only for prevState == CallStInit, CallStNonInvNegReply,
		CallStNegReply and for anything else keep the current state */
		switch mmethod {
		case sipsp.MInvite:
			newState = CallStFInv
		case sipsp.MAck:
			newState = prevState // keep state for ack
		default:
			newState = CallStFNonInv
		}
	}
end:
	e.CSeq[dir] = mcseq
	e.ReqsNo[dir]++
	// update state
	e.prevState = e.State // debugging
	e.State = newState
	// add extra event attributes from msg that are not already set
	e.Info.AddFromMsg(m, dir)
	event = updateEvent(event, e)
	if event != EvNone {
		e.evGen = EvGenReq
	}
	return newState, event
retr: // retransmission or PRACK
	return prevState, EvNone // do nothing
}

// updateStateRepl() updates the call state in a forgiving maximum
// compatibility mode (it will try to recover from skipped messages), for a
// given received reply.
// It uses the reply status code, cseq method, cseq, presence/absence of the
// totag and the "direction" of the message to check for retransmissions
// (which will not cause a state change).
// dir is the direction of the "transaction initiator": it's 0 for requests
// from the caller and  replies from the callee (totag matches exactly) and
// 1 for requests from the callee and replies from the caller (totag matches
// fromtag).
// See also updateStateReq().
// It returns the cuurent, updtead CallState and a EventType.
// The EventType is not checked for uniqueness (e.g. several call-start could
// be generated one-after-another if several 2xx arrive)
// TODO: event support for REGISTER (full with deletions and expires) and
//      SUBSCRIBE/NOTIFY (requires extra parsing)
func updateStateRepl(e *CallEntry, m *sipsp.PSIPMsg, dir int) (CallState, EventType) {
	mstatus := m.FL.Status
	mmethod := m.PV.CSeq.MethodNo
	mcseq := m.PV.CSeq.CSeqNo
	//mhastotag := !m.PV.To.Tag.Empty()
	prevState := e.State
	newState := CallStNone
	event := EvNone
	// check for retransmissions
	// in the forking case, simultaneous 2xx on multiple branches will
	// have different To tags => we could ignore them here (but it's
	// easier to handle them too in case of forked call-state)
	if replRetr(e, m, dir) ||
		mmethod == sipsp.MPrack /* ignore PRACKs */ ||
		mmethod == sipsp.MUpdate /* ignore UPDATEs */ {
		goto retr // retransmission
	}
	switch mmethod {
	case sipsp.MCancel:
		switch prevState {
		case CallStInit, CallStFInv, CallStEarlyDlg:
			// not 100% conformant, but more "compatible" with broken UAs
			newState = CallStCanceled
			event = EvCallAttempt
		default:
			newState = prevState // keep current state, ignore CANCEL repl.*/
		}
	case sipsp.MBye:
		newState = CallStByeReplied
		event = EvCallEnd // ignore the actual BYE reply code
	default:
		switch {
		case mstatus > 299:
			switch prevState {
			case CallStInit:
				// neg. reply in INIT state => we might have missed the
				// request => try to recover the call state/info from the
				// reply
				if mmethod == sipsp.MInvite {
					// here the situation is a bit ambiguous: the real state
					// might also be ESTABLISHED (neg reply for an in-dialog
					// request and all request missed so far), but without
					// seeing the requests this is the best we could do
					// (the most likely case)
					newState = CallStNegReply
				} else {
					newState = CallStNonInvNegReply
					// no event for non-INV. neg. replies
				}
			case CallStFInv, CallStEarlyDlg:
				newState = CallStNegReply
				// we might have here an auth. failure (and we want to
				// report it only if we already seen one before on this
				// dialog, handled below, outside the case:) or a failure
				// of one of the branches (in which case we still want to
				// wait to see if we get a 2xx -- we will report EvCallAttempt
				// on timeout...)
			case CallStFNonInv:
				newState = CallStNonInvNegReply
				// no event here
			default:
				newState = prevState // keep the current state
			}
			// set event / handle auth. failure
			if authFailure(mstatus) {
				if e.ReplStatus[dir] == mstatus {
					//already seen, this is the 2nd one
					event = EvAuthFailed
				}
			} /* else rely on timeout for EvCallAttempt to be sure that
			    a possible 2xx after a neg. reply is properly handled.
				If this is not desired uncomment the code below. */
			/*
				else if mmethod == sipsp.MInvite {
				event = EvCallAttempt // only for INVITEs
			} */
		case mstatus >= 200:
			switch prevState {
			case CallStInit:
				// 2xx reply for which we haven't seen the request => recover
				if mmethod == sipsp.MInvite {
					newState = CallStEstablished
					event = EvCallStart
				} else {
					newState = CallStNonInvFinished
					if mmethod == sipsp.MRegister {
						event = EvRegNew
						// TODO: look for contact and expires == 0, it might
						//       be in fact an EvRegDel
					}
				}
			case CallStNegReply:
				// allow 2xx after negative replies (e.g. branches one
				// replies with neg. reply, another with 200)
				fallthrough
			case CallStFInv, CallStEarlyDlg:
				newState = CallStEstablished
				event = EvCallStart
			case CallStEstablished:
				// do nothing
			case CallStNonInvNegReply:
				// allow 2xx after negative replies
				fallthrough
			case CallStFNonInv:
				newState = CallStNonInvFinished
				if mmethod == sipsp.MRegister {
					event = EvRegNew
					// TODO: look for contact and expires == 0, it might
					//       be in fact an EvRegDel
				}
			default:
				newState = prevState // keep the current state
			}
		default: // <= 199
			switch prevState {
			case CallStInit, CallStFInv:
				newState = CallStEarlyDlg
			default:
				newState = prevState
			}
		}
	}
	//end:
	e.ReplCSeq[dir] = mcseq
	//? only if newState =! prevState ? (not ignored?)
	e.ReplStatus[dir] = mstatus
	e.Info.overwriteAttrField(AttrReason, &m.FL.Reason, m.Buf)
	e.ReplsNo[dir]++
	e.prevState = e.State
	e.State = newState
	// add extra event attributes from msg that are not already set
	e.Info.AddFromMsg(m, dir)
	event = updateEvent(event, e)
	if event != EvNone {
		e.evGen = EvGenRepl
	}
	return newState, event
retr: // retransmission, ignore
	return prevState, EvNone
}

func updateState(e *CallEntry, m *sipsp.PSIPMsg, dir int) (CallState, EventType) {
	if m.FL.Request() {
		return updateStateReq(e, m, dir)
	}
	return updateStateRepl(e, m, dir)
}

// reported reason for internal timeouts
var timeoutReason = []byte("internal: call state timeout")

// finalTimeoutEv() should be called before destroying and expired call entry.
// It returns the final EventType
func finalTimeoutEv(e *CallEntry) EventType {

	var forcedStatus uint16
	var forcedReason *[]byte
	event := EvNone
	switch e.State {
	case CallStFInv: // un-replied INVITE, timeout
		event = EvCallAttempt
		forcedStatus = 408
		forcedReason = &timeoutReason
	case CallStEarlyDlg: // early dialog timeout
		event = EvCallAttempt
		forcedStatus = 408
		forcedReason = &timeoutReason
	case CallStEstablished: // call timeout
		event = EvCallEnd
		forcedStatus = 408
		forcedReason = &timeoutReason

	case CallStBye: // call established, BYE sent, but not replied
		event = EvCallEnd // should've been already generated on BYE
	case CallStByeReplied: // call properly terminated, final timeout
		event = EvCallEnd // should have been already generated
	case CallStCanceled:
		event = EvCallAttempt // should've been already generated
	case CallStNegReply:
		// handle auth failure followed by timeout
		if authFailure(e.ReplStatus[0]) || authFailure(e.ReplStatus[1]) {
			event = EvAuthFailed
		} else {
			// this was delayed to final timeout to catch
			// possible parallel branches 2xxs
			event = EvCallAttempt
		}

	// non INVs
	case CallStFNonInv:
		// nothing here. For REGISTERs we generate EvRegNew only on reply
		// so if no reply seen, we won't generate an EvRegDel or EvRegExpired
	case CallStNonInvNegReply:
		// we care only about REGISTERs timeouts and timeout after
		// auth. failure at this point. TODO: SUBSCRIBE
		if authFailure(e.ReplStatus[0]) || authFailure(e.ReplStatus[1]) {
			event = EvAuthFailed
		}
		// else if REGISTER, like above, do nothing
	case CallStNonInvFinished:
		if e.Method == sipsp.MRegister {
			event = EvRegExpired
		}

	case CallStInit:
		// do nothing, should never reach this.
	}
	event = updateEvent(event, e)
	if event != EvNone {
		if forcedStatus != 0 {
			e.ReplStatus[0] = forcedStatus
		}
		if forcedReason != nil {
			e.Info.overwriteAttr(AttrReason, *forcedReason)
		}
		e.evGen = EvGenTimeout
	}
	return event
}
