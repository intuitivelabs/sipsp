package calltr

import (
	"log"
	"sync"

	"andrei/sipsp"
)

// hash table and hash bucket lists

type CallEntryHash struct {
	HTable []CallEntryLst
}

func (h *CallEntryHash) Init(sz int) {
	h.HTable = make([]CallEntryLst, sz)
	for i := 0; i < len(h.HTable); i++ {
		h.HTable[i].Init()
	}
}

func (h *CallEntryHash) Destroy() {
	retry := true
	for retry {
		retry = false
		for i := 0; i < len(h.HTable); i++ {
			h.HTable[i].Lock()
			s := h.HTable[i].head.next
			for v, nxt := s, s.next; v != &h.HTable[i].head; v, nxt = nxt, nxt.next {
				if !csTimerTryStopUnsafe(v) {
					// timer is running, retry later (must unlock first)
					log.Printf("Hash Destroy: Timer running  for %p: %v\n",
						v, *v)
					retry = true
					continue
				}
				h.HTable[i].Rm(v)
				if !v.Unref() {
					// still referenced
					log.Printf("Hash Destroy: entry still referenced %p: %v\n",
						v, *v)
					//FreeCallEntry(v)
				}
			}
			h.HTable[i].Unlock()
		}
	}
	h.HTable = nil
}

func (h *CallEntryHash) Hash(buf []byte, offs int, l int) uint32 {
	return GetHash(buf, offs, l) % uint32(len(h.HTable))
}

type CallEntryLst struct {
	head CallEntry  // used only as list head (only next and prev are valid)
	lock sync.Mutex // lock
	// statistics
	entries uint
}

func (lst *CallEntryLst) Init() {
	lst.head.next = &lst.head
	lst.head.prev = &lst.head
}

func (lst *CallEntryLst) IncStats() {
	lst.entries++
}

func (lst *CallEntryLst) DecStats() {
	lst.entries--
}

func (lst *CallEntryLst) Lock() {
	lst.lock.Lock()
}

func (lst *CallEntryLst) Unlock() {
	lst.lock.Unlock()
}

func (lst *CallEntryLst) Insert(e *CallEntry) {
	e.prev = &lst.head
	e.next = lst.head.next
	e.next.prev = e
	lst.head.next = e
}

func (lst *CallEntryLst) Rm(e *CallEntry) {
	e.prev.next = e.next
	e.next.prev = e.prev
	// "mark" e as detached
	e.next = e
	e.prev = e
}

func (lst *CallEntryLst) Detached(e *CallEntry) bool {
	return e == e.next
}

// iterates on the entire lists calling f(e) for each element, until
// false is returned or the lists ends.
// WARNING: does not support removing the current element from f, see
//          ForEachSafeRm().
func (lst *CallEntryLst) ForEach(f func(e *CallEntry) bool) {
	cont := true
	for v := lst.head.next; v != &lst.head && cont; v = v.next {
		cont = f(v)
	}
}

// iterates on the entire lists calling f(e) for each element, until
// false is returned or the lists ends.
// It does not support removing the current element from f.
func (lst *CallEntryLst) ForEachSafeRm(f func(e *CallEntry) bool) {
	cont := true
	s := lst.head.next
	for v, nxt := s, s.next; v != &lst.head && cont; v, nxt = nxt, nxt.next {
		cont = f(v)
	}
}

// Find looks for a call entry corresponding to the given callid, from tag and
// to tag. It returns the best matching CallEntry, the match type and the
// match direction (0 for caller -> callee  and 1 for callee -> caller)
// It does not use internal locking. Call it between Lock() / Unlock() to
// be concurrency safe.
func (lst *CallEntryLst) Find(callid, ftag, ttag []byte, cseq uint32,
	status uint16, method sipsp.SIPMethod) (*CallEntry, CallMatchType, int) {

	var callidMatch *CallEntry
	var partialMatch *CallEntry
	var partialMDir int

	for e := lst.head.next; e != &lst.head; e = e.next {
		mt, dir := e.match(callid, ftag, ttag)
		switch mt {
		case CallFullMatch:
			//  don't FullMatch if no to-tag is present, at least
			//        not if Methods are != or this is not an ACK or
			//        CANCEL (BYE should always have a valid totag)
			if len(ttag) != 0 || method == e.Method ||
				(e.Method == sipsp.MInvite && (method == sipsp.MAck ||
					method == sipsp.MCancel)) {
				return e, mt, dir
			}
			// else:
			mt = CallPartialMatch
			fallthrough
		case CallPartialMatch:
			partialMatch, partialMDir = chooseCallIDMatch(
				e, dir, partialMatch, partialMDir, cseq, status, method)

			// continue searching for a possible better match
		case CallCallIDMatch:
			/*  some UAs reuse the same CallId with different from
			tags, at least for REGISTER reauth.
			rfc3261 doesn't explicitly forbid this (one can argue
			that even INVITEs re-sent due to a challenge are allowed to
			have a different fromtag if they are not already part of a
			dialog).
			A REGISTER resent due to an auth failure could even have
			a  different callid (rfc3261: SHOULD have the same callid),
			but we cannot handle this case.
			However we try "hard" to match REGISTER to previous REGISTER
			entries, even if the only  thing in common is the callid.
			*/
			callidMatch, _ = chooseCallIDMatch(
				e, dir, callidMatch, 0, cseq, status, method)
		case CallNoMatch: // do nothing
		}
	}
	if partialMatch == nil {
		if callidMatch != nil {
			return callidMatch, CallCallIDMatch, 0 // we don't know the dir
		}
		return nil, CallNoMatch, 0
	}
	return partialMatch, CallPartialMatch, partialMDir
}

/*
// choose best partial match between 2 CallEntry-s (with the same
//  callid), for a message with a given cseq and reply status
// (status == 0 for a request).
// dir1 & dir2 are the match directions for the respective CallEntry-s.
// Returns "best" matching call entry
func choosePartialMatch(e1 *CallEntry, dir1 int, e2 *CallEntry, dir2 int,
	cseq uint32, status uint16, method sipsp.SIPMethod) (*CallEntry, int) {

	if e1 == nil {
		return e2, dir2
	}
	if e2 == nil {
		return e1, dir1
	}
	// prefer matching methods
	if e1.Method != e2.Method {
		if e1.Method == method {
			return e1, dir1
		}
		if e2.Method == method {
			return e2, dir2
		}
	}
	// either both entries method match or neither matches with method
	// => it does not really matter what we choose

	if cseq == e1.CSeq[dir1] && cseq != e2.CSeq[dir2] {
		return e1, dir1
	}
	if cseq != e1.CSeq[dir1] && cseq == e2.CSeq[dir2] {
		return e2, dir2
	}
	if (cseq == e1.CSeq[dir1] && cseq == e2.CSeq[dir2]) ||
		(cseq > e1.CSeq[dir1] && cseq > e2.CSeq[dir2]) {
		// equal cseqs or current msg cseq > both entries cseq
		// if more partialMatches, choose the one that has a
		//   failed auth. If there are more, or there is none with
		//   failed auth, then choose the one with cseq < crt. message.
		//   If there are more, then choose the one with the lowest cseq
		if authFailure(e1.ReplStatus[dir1]) &&
			!authFailure(e2.ReplStatus[dir2]) {
			// e1 has a failed auth. => return it
			return e1, dir1
		}
		if authFailure(e2.ReplStatus[dir2]) &&
			!authFailure(e1.ReplStatus[dir1]) {
			// e2 has a failed auth. => return it
			return e2, dir2
		}
		// either both have auth failure or none => fallback to
		// using CSeq
		if e1.CSeq[dir1] > e2.CSeq[dir2] {
			return e1, dir1
		}
		return e2, dir2
	}
	// here cseq is less then both or only one of them, return the greater one
	if e1.CSeq[dir1] > e2.CSeq[dir2] {
		return e1, dir1
	}
	return e2, dir2
}
*/

// pick the best callid-only match between 2 CallEntry-s (with the same
//  callid), for a message with a given cseq and reply status
// (status == 0 for a request).
// dir1 & dir2 are the match directions for the respective CallEntry-s.
// Returns "best" matching call entry
func chooseCallIDMatch(e1 *CallEntry, dir1 int, e2 *CallEntry, dir2 int,
	cseq uint32, status uint16, method sipsp.SIPMethod) (*CallEntry, int) {

	if e1 == nil {
		return e2, dir2
	}
	if e2 == nil {
		return e1, dir1
	}
	// prefer matching methods
	if e1.Method != e2.Method {
		if e1.Method == method {
			return e1, dir1
		}
		if e2.Method == method {
			return e2, dir2
		}
	}
	// either both entries method match or neither matches with method
	// => it does not really matter what we choose
	// for a callID only match we cannot rely on the message CSeq
	// (when changing the from tag the CSeq numbering is most likely
	//  restarted), but it still probable enough that using CSeq will
	// get them most recent entry
	if cseq == e1.CSeq[dir1] && cseq != e2.CSeq[dir2] {
		return e1, dir1
	}
	if cseq != e1.CSeq[dir1] && cseq == e2.CSeq[dir2] {
		return e2, dir2
	}

	if (cseq == e1.CSeq[dir1] && cseq == e2.CSeq[dir2]) ||
		(cseq > e1.CSeq[dir1] && cseq > e2.CSeq[dir2]) {
		// equal cseqs or current msg cseq > both entries cseq
		// (e.g. in the case of REGISTER with changing from-tags )
		if authFailure(e1.ReplStatus[dir1]) && !authFailure(e2.ReplStatus[dir2]) {
			// e1 has a failed auth. => return it
			return e1, dir1
		}
		if authFailure(e2.ReplStatus[dir2]) && !authFailure(e1.ReplStatus[dir1]) {
			// e2 has a failed auth. => return it
			return e2, dir2
		}
		if authFailure(e1.ReplStatus[dir1]) && authFailure(e2.ReplStatus[dir2]) {
			//  both have auth failure => fall back to using CSeq
			// (arbitrarily pick the entry with the greater CSeq, probably
			//  more recent)
			if e1.CSeq[dir1] > e2.CSeq[dir2] {
				return e1, dir1
			}
			return e2, dir2
		}
		// either both have auth failure or none => fallback to
		// using CSeq
		if e1.CSeq[dir1] > e2.CSeq[dir2] {
			return e1, dir1
		}
		return e2, dir2
	}
	// here cseq is less then both or only one of them, return the greater one
	if e1.CSeq[dir1] > e2.CSeq[dir2] {
		return e1, dir1
	}
	return e2, dir2
}
