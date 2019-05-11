package calltr

import (
	"log"
	"sync"
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
// be concurency safe.
func (lst *CallEntryLst) Find(callid, ftag, ttag []byte) (*CallEntry, CallMatchType, int) {

	var callidMatch *CallEntry
	var partialMatch *CallEntry
	var partialMDir int

	for e := lst.head.next; e != &lst.head; e = e.next {
		mt, dir := e.match(callid, ftag, ttag)
		switch mt {
		case CallFullMatch:
			return e, mt, dir
		case CallPartialMatch:
			partialMatch = e
			partialMDir = dir
			// continue searching for a possible better match
		case CallCallIDMatch:
			/*  some UAs reuse the same CallId with different from
			tags, at least for REGISTER reauth.
			rfc3261 doesn't explicitely forbid this (one can argue
			that even INVITEs re-sent due to a challenge are allowed to
			have a different fromtag if they are not already part of a
			dialog).
			A REGISTER resent due to an auth failure could even have
			a  different callid (rfc3261: SHOULD have tehe same callid),
			but we cannot handle this case.
			*/
			if callidMatch == nil && e.Key.ToTag.Len == 0 {
				callidMatch = e // fallback if we don't find something better
			}
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
