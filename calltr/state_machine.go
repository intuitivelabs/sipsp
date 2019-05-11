package calltr

import (
	"andrei/sipsp"
)

// updateStateReq() updates the call state in a forgiving maximum compatibility
// mode (it will try to recover from skipped messages), for a given request
// message.
// It uses the message method, cseq, presence/absence of the totag and the
// "direction" of the message to check for retransmissions (which will not
// cause a state change).
// dir is the direction and it's 0 for requests from the caller and 1 for
// requests from the callee.
// See also updateStateRepl().
func updateStateReq(e *CallEntry, m *sipsp.PSIPMsg, dir int) CallState {
	mmethod := m.FL.MethodNo
	mcseq := m.PV.CSeq.CSeqNo
	mhastotag := !m.PV.To.Tag.Empty()
	prevState := e.State
	newState := CallStNone
	if mcseq < e.CSeq[dir] ||
		(mcseq == e.CSeq[dir] &&
			mmethod != sipsp.MAck && mmethod != sipsp.MCancel) ||
		mmethod == sipsp.MPrack /* ignore PRACKs */ ||
		mmethod == sipsp.MUpdate /* ignore UPDATEs */ {
		// retransmission
		goto retr
	}
	e.CSeq[dir] = mcseq
	e.ReqsNo[dir]++
	switch mmethod {
	case sipsp.MBye:
		newState = CallStBye
	case sipsp.MCancel:
		switch prevState {
		case CallStInit, CallStFInv, CallStEarlyDlg:
			// not 100% conformant, but more "compatible" with broken UAs
			newState = CallStCanceled
		default:
			newState = prevState // ignore CANCEL, keep old state
		}
	default:
		// INVITE, ACK or non-INVITE
		if mhastotag {
			switch prevState {
			case CallStInit, CallStFInv, CallStEarlyDlg:
				// reply missed somehow
				newState = CallStEstablished
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
	// update state
	e.State = newState
	return newState
retr: // retransmission or PRACK
	return prevState // do nothing
}

// updateStateRepl() updates the call state in a forgiving maximum
// compatibility mode (it will try to recover from skipped messages), for a
// given received reply.
// It uses the reply status code, cseq method, cseq, presence/absence of the
// totag and the "direction" of the message to check for retransmissions
// (which will not cause a state change).
// dir is the direction and it's 1 for replies from the caller and 0 for
// replies from the callee.
// See also updateStateReq().
func updateStateRepl(e *CallEntry, m *sipsp.PSIPMsg, dir int) CallState {
	mstatus := m.FL.Status
	mmethod := m.PV.CSeq.MethodNo
	mcseq := m.PV.CSeq.CSeqNo
	//mhastotag := !m.PV.To.Tag.Empty()
	prevState := e.State
	newState := CallStNone
	// check for retransmissions
	// in the forking case, simultaneous 2xx on multiple branches will
	// have differetn To tags => we can ignore them here
	if mcseq < e.CSeq[dir] || mcseq < e.ReplCSeq[dir] ||
		(mcseq == e.ReplCSeq[dir] && mstatus <= e.ReplStatus[dir]) ||
		mmethod == sipsp.MPrack /* ignore PRACKs */ ||
		mmethod == sipsp.MUpdate /* ignore UPDATEs */ {
		goto retr // retransmission
	}
	e.ReplCSeq[dir] = mcseq
	e.ReplStatus[dir] = mstatus
	e.ReplsNo[dir]++
	switch mmethod {
	case sipsp.MCancel:
		switch prevState {
		case CallStInit, CallStFInv, CallStEarlyDlg:
			// not 100% conformant, but more "compatible" with broken UAs
			newState = CallStCanceled
		default:
			newState = prevState // keep current state, ignore CANCEL repl.*/
		}
	case sipsp.MBye:
		newState = CallStByeReplied
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
				}
			case CallStFInv, CallStEarlyDlg:
				newState = CallStNegReply
			case CallStFNonInv:
				newState = CallStNonInvNegReply
			default:
				newState = prevState // keep the current state
			}
		case mstatus >= 200:
			switch prevState {
			case CallStInit:
				// 2xx reply for which we haven't seen the request => recover
				if mmethod == sipsp.MInvite {
					newState = CallStEstablished
				} else {
					newState = CallStNonInvFinished
				}
			case CallStFInv, CallStEarlyDlg, CallStEstablished:
				newState = CallStEstablished
			case CallStFNonInv:
				newState = CallStNonInvFinished
			default:
				newState = prevState // keep the current state
			}
		default:
			switch prevState {
			case CallStInit, CallStFInv:
				newState = CallStEarlyDlg
			default:
				newState = prevState
			}
		}
	}
	//end:
	e.State = newState
	return newState
retr: // retransmission, ignore
	return prevState

}

func updateState(e *CallEntry, m *sipsp.PSIPMsg, dir int) CallState {
	if m.FL.Request() {
		return updateStateReq(e, m, dir)
	}
	return updateStateRepl(e, m, dir)
}
