package calltr

import (
	"andrei/sipsp"
	"andrei/sipsp/bytescase"
)

type TimeoutS uint32

// return true if this looks like a request retr.
func reqRetr(e *CallEntry, m *sipsp.PSIPMsg, dir int) bool {
	mcseq := m.PV.CSeq.CSeqNo
	mmethod := m.FL.MethodNo
	maxCSeq := e.CSeq[dir]
	if e.CSeq[dir] < e.ReplCSeq[dir] {
		maxCSeq = e.ReplCSeq[dir]
	}
	if mcseq < maxCSeq ||
		(mcseq == maxCSeq &&
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
	maxCSeq := e.CSeq[dir]
	if e.CSeq[dir] < e.ReplCSeq[dir] {
		maxCSeq = e.ReplCSeq[dir]
	}
	if mcseq < maxCSeq ||
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
// It returns the current, updated CallState, the corresponding timeout, the
// timeout flags and an EventType.
// The EventType is not checked for uniqueness (e.g. several call-start could
// be generated one-after-another if several 2xx arrive)
// TODO: look at dir when deciding how/what to update
// unsafe, MUST be called w/ lock held or if no parallel access is possible
func updateStateReq(e *CallEntry, m *sipsp.PSIPMsg, dir int) (CallState, TimeoutS, TimerUpdateF, EventType) {
	mmethod := m.FL.MethodNo
	mcseq := m.PV.CSeq.CSeqNo
	mhastotag := !m.PV.To.Tag.Empty()
	prevState := e.State
	newState := CallStNone
	event := EvNone
	toFlags := FTimerUpdForce
	if reqRetr(e, m, dir) ||
		mmethod == sipsp.MPrack /* ignore PRACKs */ ||
		mmethod == sipsp.MUpdate /* ignore UPDATEs */ {
		// retransmission
		goto retr
	}
	switch mmethod {
	case sipsp.MBye:
		// accept BYE only for INV dialogs
		switch prevState {
		case CallStInit, CallStFInv, CallStEarlyDlg, CallStEstablished,
			CallStNegReply:
			newState = CallStBye
			event = EvCallEnd // for extra reliability: both on BYE and BYE repl.
			// force-update the timeout
		case CallStBye, CallStByeReplied:
			fallthrough // do nothing, keep state
		default:
			newState = prevState
			toFlags = FTimerUpdGT // don't reduce the timeout
		}
	case sipsp.MCancel:
		switch prevState {
		case CallStInit, CallStFInv, CallStEarlyDlg:
			// not 100% conformant, but more "compatible" with broken UAs
			newState = CallStCanceled
			// we will generate CallAttempt on timeout to allow
			// catching late 2XXs
			// event = EvCallAttempt
			// force-update the timeout
		default:
			newState = prevState  // ignore CANCEL, keep old state
			toFlags = FTimerUpdGT // don't reduce the timeout
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
				switch mmethod {
				// CANCEL and BYE handled above
				case sipsp.MAck:
					// ACK can be to 2xx or to negative reply
					// at this point (1st CallStFInv or CallStEarlyDlg)
					// we can't tell => ignore
					newState = prevState  // keep the same state
					toFlags = FTimerUpdGT // don't reduce the timeout
				case sipsp.MNotify, sipsp.MUpdate, sipsp.MPrack:
					// NOTIFY cannot be "trusted" some UAS send notifies
					// on early dialog and it has nothing to do with the
					// call.
					// UPDATE is by definition used in early-dialog only and
					// it does not signify any call establishment
					// same for PRACK
					newState = prevState  // keep the same state
					toFlags = FTimerUpdGT // don't reduce the timeout
				default:
					// in-dialog request that's not ACK, PRACK, NOTIFY, UPDATE,
					// CANCEL or BYE
					// => probably we missed a 2xx => recover
					newState = CallStEstablished
					event = EvCallStart
					toFlags = FTimerUpdGT // don't reduce the timeout
				}
			default:
				// Established, NegReply, NonInvNegReply, NonInvFinished
				// Canceled, BYE, BYE reply

				// REGISTER hack: update timeout only if bigger then current
				// (to allow keeping long-term REGISTER entry that will
				//  catch REGISTER re-freshes), both for REGISTER refreshes
				// and for other messages in the same "dialog" (e.g. OPTIONs)
				if mmethod == sipsp.MRegister || e.Method == sipsp.MRegister {
					// update Contact...
					if mmethod == sipsp.MRegister {
						if mC := m.PV.Contacts.GetContact(0); mC != nil {
							e.Info.OverwriteAttrField(AttrContact,
								&mC.URI, m.Buf)
						}
					}
				}
				toFlags = FTimerUpdGT // don't reduce the timeout
				newState = prevState  // keep same state
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
		 - a "new" REGISTER refresh for a contact (some UAs send them
		   without the to-tag but with the same callid and from-tag as
		   the original REGITERs and increased CSeq).
		 - some strange broken call
		 - a to-tag less OPTIONS for a REGISTER like above
		*/
		/* we allow for missed replies, if not execute the following
		code only for prevState == CallStInit, CallStNonInvNegReply,
		CallStNegReply and for anything else keep the current state */
		switch mmethod {
		case sipsp.MInvite:
			if prevState == CallStInit || prevState == CallStNegReply {
				// e.g.: INVITE after auth failure
				newState = CallStFInv
			} else {
				// INVITE w/o toTag and cseq++ in early dialog  or established
				// possible due to matching toTag="" INVITE to existing
				// call-entries with to-tag!=""
				// In this case update cseq, but keep state
				newState = prevState
				toFlags = FTimerUpdGT // don't reduce the timeout
			}
		case sipsp.MAck:
			// ACK w/o to-tag .... should not happen
			newState = prevState  // keep state for ack
			toFlags = FTimerUpdGT // don't reduce the timeout
		case sipsp.MRegister:
			// REGISTER refresh hack: update timeout only if bigger
			// then current (to allow keeping long-term REGISTER
			// entry that will catch refreshes)
			if prevState != CallStInit {
				toFlags = FTimerUpdGT
				// keep state, a REG refresh should not change it
				// (otherwise due to the match REGs w/o to-tags hack a
				// REG-refresh  might get here and reset the state)
				newState = prevState // keep state
				// update Contact...
				if mC := m.PV.Contacts.GetContact(0); mC != nil {
					e.Info.OverwriteAttrField(AttrContact, &mC.URI, m.Buf)
				}
			} else {
				newState = CallStFNonInv
			}
		default:
			if prevState != CallStInit && mmethod != e.Method {
				// another force-matched message that has
				// a different method then the orig. message should
				// not cause state changes or timeout resets
				// (note that CANCEL is caught above so we don't have to
				//  worry about it here)
				toFlags = FTimerUpdGT // allow timer increase but no dec.
				newState = prevState  // keep state
			} else {
				newState = CallStFNonInv
			}
		}
	}
end:
	e.CSeq[dir] = mcseq
	e.ReqsNo[dir]++
	// update state
	e.prevState.Add(e.State) // debugging
	e.lastMethod[dir] = mmethod
	e.lastMsgs.AddReq(mmethod, dir, 0)
	e.State = newState
	// add extra event attributes from msg that are not already set
	e.Info.AddFromMsg(m, dir)
	event = updateEvent(event, e)
	if event != EvNone {
		e.evGen = EvGenReq
	}
	return newState, TimeoutS(newState.TimeoutS()), toFlags, event
retr: // retransmission or PRACK
	newState = prevState
	toFlags = FTimerUpdGT // update timer only if not already greater...
	e.ReqsRetrNo[dir]++
	e.lastMsgs.AddReq(mmethod, dir, 1)
	return prevState, TimeoutS(prevState.TimeoutS()), toFlags, EvNone
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
// It returns the current, updated CallState, the corresponding timeout, the
// timeout flags and an EventType.
// The EventType is not checked for uniqueness (e.g. several call-start could
// be generated one-after-another if several 2xx arrive)
// TODO: event support for REGISTER (full with deletions and expires) and
//      SUBSCRIBE/NOTIFY (requires extra parsing)
// TODO: REG timeout = Max Expires, or if bad value 3600 (rfc3261) ??
// TODO: look at dir when deciding how/what to update
// unsafe, MUST be called w/ lock held or if no parallel access is possible
func updateStateRepl(e *CallEntry, m *sipsp.PSIPMsg, dir int) (CallState, TimeoutS, TimerUpdateF, EventType) {
	var to TimeoutS
	toFlags := FTimerUpdForce
	mstatus := m.FL.Status
	mmethod := m.PV.CSeq.MethodNo
	mcseq := m.PV.CSeq.CSeqNo
	mhastotag := !m.PV.To.Tag.Empty()
	prevState := e.State
	newState := CallStNone
	event := EvNone
	// check for retransmissions
	// in the forking case, simultaneous 2xx on multiple branches will
	// have different To tags => we could ignore them here (but it's
	// easier to handle them too in case of forked call-state)
	if replRetr(e, m, dir) ||
		mmethod == sipsp.MPrack /* ignore PRACKs */ ||
		mmethod == sipsp.MUpdate /* ignore UPDATEs */ ||
		mmethod == sipsp.MAck /* should never happen, but...*/ {
		goto retr // retransmission
	}
	switch mmethod {
	case sipsp.MCancel:
		switch prevState {
		case CallStInit, CallStFInv, CallStEarlyDlg:
			// not 100% conformant, but more "compatible" with broken UAs
			// force-reset the timeout
			newState = CallStCanceled
			event = EvCallAttempt
		default:
			newState = prevState  // keep current state, ignore CANCEL repl.*/
			toFlags = FTimerUpdGT // don't reduce the timeout
		}
	case sipsp.MBye:
		//  accept BYE only for INV dialogs
		switch prevState {
		case CallStInit, CallStFInv, CallStEarlyDlg, CallStEstablished,
			CallStBye, CallStNegReply:
			newState = CallStByeReplied
			// force-reset the timeout ...
			event = EvCallEnd // ignore the actual BYE reply code
		case CallStByeReplied:
			fallthrough // do nothing, keep state
		default:
			newState = prevState  // keep current state, ignore CANCEL repl.*/
			toFlags = FTimerUpdGT // don't reduce the timeout
		}
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
					// request and all requests missed so far), but without
					// seeing the requests this is the best we could do
					// (the most likely case)
					newState = CallStNegReply
				} else {
					newState = CallStNonInvNegReply
					// no event for non-INV. neg. replies
				}
			case CallStFInv, CallStEarlyDlg:
				if mmethod == sipsp.MInvite {
					newState = CallStNegReply
					// we might have here an auth. failure (and we want to
					// report it only if we already seen one before on this
					// dialog, handled below, outside the case:) or a failure
					// of one of the branches (in which case we still want to
					// wait to see if we get a 2xx -- we will report EvCallAttempt
					// on timeout...)
				} else {
					// neg. reply, but not to the INVITE, (e.g. to an UPDATE
					//  or PRACK) ignore...
					// (BYE and CANCEL are handled above)
					newState = prevState  // keep the current state
					toFlags = FTimerUpdGT // don't reduce the timeout
				}
			case CallStFNonInv:
				newState = CallStNonInvNegReply
				// no event here
			case CallStNonInvFinished:
				// REGISTER HACK: if the neg reply is to a REGISTER refresh
				// matching a "REGISTER-extended-lifetime" entry, update
				// the timeout only if it would be greater then current
				// lifetime.
				// Ignore also possible negative replies to OPTIONs (or
				// other methods) sent in the same "dialog"
				/*
					if mmethod == sipsp.MRegister ||
						e.Method == sipsp.MRegister {
						toFlags = FTimerUpdGT
					} */
				// negative reply after 2xx, ignore, see the
				// OPTIONS after REGISTER example above
				toFlags = FTimerUpdGT // don't reduce the timeout
				newState = prevState  // keep the current state
			default:
				newState = prevState  // keep the current state
				toFlags = FTimerUpdGT // don't reduce the timeout
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
						// reply to REGISTER without seen the request
						event = EvRegNew
						exp, _ := m.PV.MaxExpires()
						to = TimeoutS(exp)
						// if to == 0 it is either set explicitly to 0
						// in the REGISTER or no Expires or Contact headers
						// are present, in both case => delete
						// note however that a REGISTER reply with a 0 expire
						// contact is highly improbable.
						if to == 0 {
							// 0 timeout => it's a delete
							event = EvRegDel
						}
					}
				}
			case CallStNegReply:
				// allow 2xx after negative replies (e.g. branches one
				// replies with neg. reply, another with 200)
				fallthrough
			case CallStFInv, CallStEarlyDlg:
				if mmethod == sipsp.MInvite {
					newState = CallStEstablished
					event = EvCallStart
				} else {
					// 2xx to some other in-dialog request
					// BYE and CANCEL are handled above, we might have
					// an UPDATE, PRACK or some strange early NOTIFY reply
					// ignore ...
					newState = prevState  // keep the current state
					toFlags = FTimerUpdGT // don't reduce the timeout
				}
			case CallStEstablished:
				// do nothing
				newState = prevState  // keep the current state
				toFlags = FTimerUpdGT // don't reduce the timeout
			case CallStNonInvNegReply:
				// allow 2xx after negative replies
				fallthrough
			case CallStFNonInv:
				if mmethod == e.Method {
					newState = CallStNonInvFinished
					if mmethod == sipsp.MRegister {
						// REGISTER special HACK
						event, to, toFlags = handleRegRepl(e, m)
					}
				} else {
					// ignore, reply to something else, e.g. OPTIONS sent
					// as pings alongside REGISTERs
					newState = prevState  // keep the current state
					toFlags = FTimerUpdGT // don't reduce the timeout
				}
			case CallStNonInvFinished:
				newState = prevState // keep the current state
				if mmethod == sipsp.MRegister {
					// REGISTER special HACK
					event, to, toFlags = handleRegRepl(e, m)
				} else {
					// e.g. other message matching a REGISTER created entry
					// like OPTIONS sent by some UACs
					toFlags = FTimerUpdGT
				}
			default:
				newState = prevState  // keep the current state
				toFlags = FTimerUpdGT // don't reduce the timeout
			}
		case mstatus >= 101: // 101-199 early dialog
			// 3 possible cases:
			//   1. provisional reply before any final reply
			//   2. provisional reply in-dialog after the dialog
			//      was established
			//   3. provisional reply to a REGISTER-refresh (that
			//       matches the extended REGISTER call-entry)
			//  For 2 & 3 the timeout should be changed only if the result
			//  would be greater then the current timeout
			switch prevState {
			case CallStInit, CallStFInv:
				if mhastotag {
					newState = CallStEarlyDlg
				} else {
					toFlags = FTimerUpdGT
					newState = prevState
				}
			case CallStNonInvFinished:

				// REGISTER HACK
				/*
					if mmethod == sipsp.MRegister &&
						(e.Flags&CFRegReplacedHack != 0) {
						toFlags = FTimerUpdGT
					}
					newState = prevState
				*/
				fallthrough
			default:
				toFlags = FTimerUpdGT
				newState = prevState
			}
		default: // 100 or invalid: ignore just update timeout
			toFlags = FTimerUpdGT
			newState = prevState
		}
	}
	//end:
	e.ReplCSeq[dir] = mcseq
	//? only if newState =! prevState ? (not ignored?)
	if mmethod == e.Method {
		// status updates only for replies to dialog-creation requests
		// and its re-freshes
		// a possible exception could be made for
		//   e.Method == MInvite & mmethod = MCancel
		e.ReplStatus[dir] = mstatus
		e.Info.OverwriteAttrField(AttrReason, &m.FL.Reason, m.Buf)
	}
	e.lastReplStatus[dir] = mstatus
	e.lastMsgs.AddRepl(mstatus, dir, 0)
	e.ReplsNo[dir]++
	e.prevState.Add(e.State)
	e.State = newState
	// add extra event attributes from msg that are not already set
	e.Info.AddFromMsg(m, dir)
	event = updateEvent(event, e)
	if event != EvNone {
		e.evGen = EvGenRepl
	}
	if to == 0 {
		to = TimeoutS(newState.TimeoutS())
	}
	return newState, to, toFlags, event
retr: // retransmission, ignore
	newState = prevState
	e.ReplsRetrNo[dir]++
	e.lastMsgs.AddRepl(mstatus, dir, 1)
	toFlags = FTimerUpdGT // update timer only if not already greater...
	to = TimeoutS(prevState.TimeoutS())
	return prevState, to, toFlags, EvNone
}

// unsafe, MUST be called w/ lock held or if no parallel access is possible
func updateState(e *CallEntry, m *sipsp.PSIPMsg, dir int) (CallState, TimeoutS, TimerUpdateF, EventType) {
	if m.FL.Request() {
		return updateStateReq(e, m, dir)
	}
	return updateStateRepl(e, m, dir)
}

// reported reason for internal timeouts
var timeoutReason = []byte("internal: call state timeout")

// finalTimeoutEv() should be called before destroying and expired call entry.
// It returns the final EventType
// unsafe, MUST be called w/ lock held or if no parallel access is possible
func finalTimeoutEv(e *CallEntry) EventType {

	var forcedStatus uint16
	var forcedReason *[]byte
	event := EvNone
	e.Flags |= CFTimeout
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
		if e.Method == sipsp.MRegister && !e.EvFlags.Test(EvRegDel) {
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
			e.Info.OverwriteAttr(AttrReason, *forcedReason)
		}
		e.evGen = EvGenTimeout
	}
	return event
}

// if m contains c, it return true,  expire_present and corresp. expire value
// else false, false, 0
// if the contact has no expire, but an Expire header field is present,
// its value will be returned (and true for expire_present).
func msgMatchContact(m *sipsp.PSIPMsg, c []byte) (bool, bool, uint32) {
	if !m.PV.Contacts.Parsed() || m.PV.Contacts.N == 0 || len(c) == 0 {
		// no contacts
		return false, false, 0
	}

	found := false
	var exp uint32
	hasExp := false
	// TODO: handle more contacts?
	// For now compare the contacts returned in
	//       the reply with the 1st contact in the
	//       original REGISTER
	//mCNo := m.PV.Contacts.VNo()
	var pCuri sipsp.PsipURI
	err1, _ := sipsp.ParseURI(c, &pCuri)

	for n := 0; n < m.PV.Contacts.N; /*mCNo*/ n++ {
		var mPCuri sipsp.PsipURI
		//mCuri := m.PV.Contacts.Vals[n].URI.Get(m.Buf)
		mC := m.PV.Contacts.GetContact(n)
		if mC == nil {
			continue
		}
		mCuri := mC.URI.Get(m.Buf)
		err2, _ := sipsp.ParseURI(mCuri, &mPCuri)
		if (err1 == 0 && err2 == 0 &&
			sipsp.URICmpShort(&pCuri, c, &mPCuri, mCuri, sipsp.URICmpAll)) ||
			// fallback to normal string compare if unparsable uris:
			(err1 != 0 && err2 != 0 && bytescase.CmpEq(mCuri, c)) {
			// match
			found = true
			exp = mC.Expires
			hasExp = mC.HasExpires
			if !hasExp {
				if m.PV.Expires.Parsed() {
					exp = m.PV.Expires.UIVal
					hasExp = true
				}
			}
			break // from for
		}
	}
	// If the contact not found in contact list there are 2
	// possibilities: either it does not exists =>
	// deleted or it did not fit in the contact list
	// (e.g. VNo() < N -> N-VNo() missing contacts)
	if !found {
		if m.PV.Contacts.VNo() == m.PV.Contacts.N {
			// really missing
			exp = 0
		} else {
			// TODO:
			// it might be present but we didn't parse it
			// try parsing m.PV.Contacts.LastVal
			// if not found iterate on all headers looking for
			// contact
			// or try to re-parse the whole message if Contacts.HNo > 1
			// with enough contact space?
			// e.g.: newmsg.Init(...make([]PFromBody, m.PV.Contacts.N)) ...
			// otherwise ParseAllContacts Contacs.LastVal ?
		}
	}
	return found, hasExp, exp
}

// returns the event type, new timeout or 0 (meaning the caller should use the
//  default) and timeout update flags (force update or extend-only timeout).
func handleRegRepl(e *CallEntry, m *sipsp.PSIPMsg) (event EventType, to TimeoutS, toFlags TimerUpdateF) {
	toFlags = FTimerUpdForce
	event = EvRegNew
	// TODO: if not all Contacts parsed, parse manually
	//       REGISTER contacts
	savedC := e.Info.Attrs[AttrContact].Get(e.Info.buf)
	if len(savedC) == 0 {
		// no contact in the request
		// it's either a "ping" REGISTER or the call-entry
		// was created from a REG reply w/ no contact (?)
		// in either case we generate no event
		event = EvNone
		to = 0                // let caller decide on the default timeout
		toFlags = FTimerUpdGT // allow only extending the timeout
		/*
			exp, _ := m.PV.MaxExpires()
			to = TimeoutS(exp)
		*/
	} else if len(savedC) == 1 && savedC[0] == '*' {
		// "*" contact - consider a reply the delete
		//  confirmation
		event = EvRegDel
		to = 0
		// default: force truncate-timeout (FTimerUpdForce)
	} else if found, hasExp, exp := msgMatchContact(m, savedC); found {
		if hasExp && exp == 0 {
			// contact with 0 expire
			event = EvRegDel
			to = 0
		} else {
			to = TimeoutS(exp + Cfg.RegDelta)
		}
	} else { // not found
		event = EvRegDel
		to = 0
	}
	// aor := m.PV.GetTo().URI.Get(m.Buf) // byte slice w/ To uri
	if event == EvRegNew {
		// HACK: it's a new REG, in case this is an old
		// recycled entry clear the EvRegDel flag
		e.EvFlags.Clear(EvRegDel)
	} else if event == EvRegDel {
		e.EvFlags.Clear(EvRegNew) // clear RegNew to see them after a del
	}
	return
}
