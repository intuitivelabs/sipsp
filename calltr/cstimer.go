package calltr

import (
	"log"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"
)

// timers and timer related functions
type TimerInfo struct {
	Expire time.Time
	Handle *time.Timer
	done   int32 // terminated timers set this to 1
	// TODO: eg. expire, timer handle, list connector ...
}

/*
func (t *TimerInfo) UpdateSec(s int64) {
	t.Update(time.Duration(s) * time.Second)
}

// Unsafe, must be called w/ locking
func (t *TimerInfo) Update(after time.Duration) {
	newExpire := time.Now().Add(after)
	if newExpire.Before(t.Expire) {
		// have to delete and re-add the timer
	}
	// else extend expire
	t.Expire = newExpire
}
*/

func csTimerInitUnsafe(cs *CallEntry, after time.Duration) {
	cs.Timer.Expire = time.Now().Add(after)
	cs.Timer.Handle = nil
	cs.Timer.done = 0
}

// Unsafe, must be called w/ locking
// csTimerInit must be called first
func csTimerStartUnsafe(cs *CallEntry) bool {

	handleAddr := (*unsafe.Pointer)(unsafe.Pointer(&cs.Timer.Handle))

	callstTimer := func() {
		now := time.Now()
		// allow for small errors
		expire := cs.Timer.Expire.Add(-time.Second / 10) // sub sec/10
		if expire.Before(now) || expire.Equal(now) {
			ev := EvNone
			var evd *EventData
			if cs.evHandler != nil {
				evd = &EventData{}
				buf := make([]byte, EventDataMaxBuf())
				evd.Init(buf)
			}
			// if expired remove cs from hash
			cstHash.HTable[cs.hashNo].Lock()
			removed := false
			// check again, in case we are racing with an Update
			expire := cs.Timer.Expire.Add(-time.Second / 10) // sub sec/10
			if expire.Before(now) || expire.Equal(now) {
				cstHash.HTable[cs.hashNo].Rm(cs)
				cstHash.HTable[cs.hashNo].DecStats()
				atomic.StoreInt32(&cs.Timer.done, 1)
				removed = true
				ev = finalTimeoutEv(cs)
				if ev != EvNone && evd != nil {
					// event not seen before, report...
					// fill event data while locked, but process it
					// once unlocked
					evd.Fill(ev, cs)
				}
			}
			cstHash.HTable[cs.hashNo].Unlock()
			// mark timer as dead/done
			if removed {
				// call event callback, outside the hash lock
				if ev != EvNone && evd != nil && cs.evHandler != nil {
					cs.evHandler(evd)
				}
				cs.Unref()
				return
			} // else fall-through
		}
		/* else if timeout extended reset timer */
		// make sure the timer is set, before executing
		for atomic.LoadPointer(handleAddr) == nil {
			runtime.Gosched()
		}
		cs.Timer.Handle.Reset(cs.Timer.Expire.Sub(now))
	}

	// sanity checks
	if atomic.LoadPointer(handleAddr) != nil ||
		atomic.LoadInt32(&cs.Timer.done) != 0 {
		log.Panicf("csTimerStart called with un-init timer %p : %v\n",
			cs, *cs)
		return false
	}
	// timer routine
	h := time.AfterFunc(cs.Timer.Expire.Sub(time.Now()), callstTimer)
	if h == nil {
		return false
	}
	atomic.StorePointer(handleAddr, unsafe.Pointer(h))

	return true
}

// returns true if the timer was stopped, false if it expired or was already
// removed.
// must be called with corresp. hash lock held.
func csTimerTryStopUnsafe(cs *CallEntry) bool {
	h := cs.Timer.Handle
	if h == nil || atomic.LoadInt32(&cs.Timer.done) != 0 {
		// already removed or expired by its own
		return true // it's stopped for sure
	}
	// try to stop the timer. If Stop fails it means the timer might
	// be either expired, running or already removed.
	// Since nobody else is supposed to remove the timer and start/stop
	// races are not supposed to happen it means the timer cannot be
	// already removed at this point =>  expired or running
	// However if it already expired it would remove the call entry from
	// the hash => not reachable (before trying to remove the timer
	// one should always check if the entry is still in the hash)
	// => the only possibility is the timer is running now.
	// There's not much we ca do in this case: we cannot wait for it to finish
	// because we would deadlock on the hash lock (which the timer tries to
	// acquire). We could unlock, runtime.Gosched(), lock again, check if
	// entry still in the hash and retry stopping the timer, but this should
	// be done outside this function (which is not supposed to have as
	// possible side-efect unlocking the hash and possibly making the
	// current call entry invalid).
	return h.Stop()
}

func csTimerUpdateTimeoutUnsafe(cs *CallEntry, after time.Duration) bool {
	newExpire := time.Now().Add(after)
	if cs.Timer.Expire.After(newExpire) {
		// timeout reduced => have to stop & re-add
		cs.Timer.Expire = newExpire
		if csTimerTryStopUnsafe(cs) {
			// re-init timer preserving the handle
			cs.Timer.done = 0
			cs.Timer.Expire = time.Now().Add(after)
			if cs.Timer.Handle.Reset(after) {
				log.Printf("WARNING: csTimerUpdateTimeoutUnsafe:"+
					" reset active timer  failed for call entry %p: %v\n",
					cs, *cs)
			}
			return true
		}
		// stop failed, means the timer is running now => update failed
		log.Printf("WARNING: csTimerUpdateTimeoutUnsafe:"+
			"update timer  failed for call entry %p: %v with %d ns\n",
			cs, *cs, after)
		return false
	}
	cs.Timer.Expire = newExpire
	return true
}
