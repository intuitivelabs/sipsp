//+build alloc_pool

package calltr

import (
	"log"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"
)

const AllocCallsPerEntry = 2

// array of sync.pool, each element containing a  pool of
// raw buffer (&byte[0]) of size index * AllocRoundTo
var poolBuffs = make([]sync.Pool, MemPoolsNo)

// pool for allocating CallEntry
var poolCallEntry sync.Pool

// pool for allocating RegEntry
var poolRegEntry sync.Pool

// AllocCallEntry allocates a CallEntry and the CallEntry.Key.buf.
// The Key.buf will be keySize bytes length and info.buf infoSize.
// It might return nil if the memory limits are exceeded.
// Note: this version allocates a separate CallEntry and a buffer using
//       a sync.pool array for the various requested sizes
//       (the size is round-up to AllocRoundTo).
func AllocCallEntry(keySize, infoSize uint) *CallEntry {
	var n *CallEntry
	CallEntryAllocStats.NewCalls.Inc(1)
	callEntrySize := uint(unsafe.Sizeof(*n))
	totalBufSize := keySize + infoSize
	totalBufSize = ((totalBufSize-1)/AllocRoundTo + 1) * AllocRoundTo //round up
	var buf []byte
	pNo := int(totalBufSize / AllocRoundTo)
	if pNo < len(poolBuffs) {
		p, _ := poolBuffs[pNo].Get().(unsafe.Pointer)
		if p != nil {
			slice := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
			slice.Data = uintptr(p)
			slice.Len = int(totalBufSize)
			slice.Cap = int(totalBufSize)
			runtime.KeepAlive(p)
			CallEntryAllocStats.PoolHits[pNo].Inc(1)
		} else {
			CallEntryAllocStats.PoolMiss[pNo].Inc(1)
			// not in pool, alloc new
			buf = make([]byte, totalBufSize)
		}
	} else { // size too big for pools, alloc new
		buf = make([]byte, totalBufSize)
	}
	if buf == nil {
		CallEntryAllocStats.Failures.Inc(1)
		return nil
	}
	n, _ = poolCallEntry.Get().(*CallEntry)
	if n == nil {
		n = new(CallEntry)
		if n == nil {
			if pNo < len(poolBuffs) {
				poolBuffs[pNo].Put(unsafe.Pointer(&buf[0]))
			}
			CallEntryAllocStats.Failures.Inc(1)
			return nil
		}
		// DBG: extra debugging: when about to be garbage collected, check if
		// the entry was marked as free from FreeCallEntry(), otherwise report
		// a BUG.
		runtime.SetFinalizer(n, func(c *CallEntry) {
			if c.hashNo != (^uint32(0) - 1) {
				BUG("Finalizer: non-freed CallEntry about to be "+
					"garbage collected %p hashNo %x refCnt %x %p key %q:%q:%q\n",
					c, c.hashNo, c.refCnt, c.regBinding,
					c.Key.GetFromTag, c.Key.GetToTag, c.Key.GetCallID())
			}
		},
		)
	}
	n.hashNo = ^uint32(0) // DBG: set invalid hash
	n.Key.Init(buf[:keySize])
	n.Info.Init(buf[keySize:])
	CallEntryAllocStats.TotalSize.Inc(uint(totalBufSize + callEntrySize))
	if pNo < len(CallEntryAllocStats.Sizes) {
		CallEntryAllocStats.Sizes[pNo].Inc(1)
	} else {
		CallEntryAllocStats.Sizes[len(CallEntryAllocStats.Sizes)-1].Inc(1)
	}
	if int(callEntrySize)/AllocRoundTo < len(CallEntryAllocStats.Sizes) {
		CallEntryAllocStats.Sizes[callEntrySize/AllocRoundTo].Inc(1)
	} else {
		CallEntryAllocStats.Sizes[len(CallEntryAllocStats.Sizes)-1].Inc(1)
	}
	return n

}

// FreeCallEntry frees a CallEntry allocated with NewCallEntry.
// Note: this version is for separatly "allocated" CallEntry and CallEntry.buf.
func FreeCallEntry(e *CallEntry) {
	CallEntryAllocStats.FreeCalls.Inc(1)
	callEntrySize := unsafe.Sizeof(*e)
	totalBufSize := cap(e.Key.buf)
	// sanity checks
	if totalBufSize != (len(e.Key.buf) + len(e.Info.buf)) {
		log.Panicf("FreeCallEntry buffer size mismatch: %d != %d + %d "+
			" for CallEntry: %p , buf %p\n",
			totalBufSize, len(e.Key.buf), len(e.Info.buf),
			e, &e.Key.buf[0])
	}
	if v := atomic.LoadInt32(&e.refCnt); v != 0 {
		log.Panicf("FreeCallEntry called for a referenced entry: %p ref: %d\n",
			e, e.refCnt)
	}
	if totalBufSize/AllocRoundTo < len(poolBuffs) {
		poolBuffs[totalBufSize/AllocRoundTo].Put(unsafe.Pointer(&e.Key.buf[0]))
	}
	e.Key.buf = nil
	e.Info.buf = nil
	*e = CallEntry{}          // DBG: zero everything
	e.hashNo = ^uint32(0) - 1 // DBG: set invalid hash (mark as free'd)
	CallEntryAllocStats.TotalSize.Dec(uint(totalBufSize) + uint(callEntrySize))
	poolCallEntry.Put(e)
}

// AllocRegEntry allocates a RegEntry and the RegEntry.buf.
// The RegEntry.buf will be bufSize bytes length.
// It might return nil if the memory limits are exceeded.
func AllocRegEntry(bufSize uint) *RegEntry {
	var n *RegEntry
	RegEntryAllocStats.NewCalls.Inc(1)
	totalBufSize := bufSize
	totalBufSize = ((totalBufSize-1)/AllocRoundTo + 1) * AllocRoundTo //round up

	var buf []byte
	pNo := int(totalBufSize / AllocRoundTo)
	if pNo < len(poolBuffs) {
		p, _ := poolBuffs[pNo].Get().(unsafe.Pointer)
		if p != nil {
			slice := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
			slice.Data = uintptr(p)
			slice.Len = int(totalBufSize)
			slice.Cap = int(totalBufSize)
			runtime.KeepAlive(p)
			RegEntryAllocStats.PoolHits[pNo].Inc(1)
		} else {
			RegEntryAllocStats.PoolMiss[pNo].Inc(1)
			// not in pool, alloc new
			buf = make([]byte, totalBufSize)
		}
	} else { // size too big for pools, alloc new
		buf = make([]byte, totalBufSize)
	}
	if buf == nil {
		RegEntryAllocStats.Failures.Inc(1)
		return nil
	}
	n, _ = poolRegEntry.Get().(*RegEntry)
	if n == nil {
		n = new(RegEntry)
		if n == nil {
			if pNo < len(poolBuffs) {
				poolBuffs[pNo].Put(unsafe.Pointer(&buf[0]))
			}
			RegEntryAllocStats.Failures.Inc(1)
			return nil
		}
		// extra debugging: when about to be garbage collected, check if
		// the entry was marked as free from FreeCallEntry(), otherwise report
		// a BUG.
		runtime.SetFinalizer(n, func(r *RegEntry) {
			if r.hashNo != (^uint32(0) - 1) {
				BUG("Finalizer: non-freed RegEntry about to be "+
					"garbage collected %p hashNo %x refCnt %x ce %p key %q:%q\n",
					r, r.hashNo, r.refCnt, r.ce,
					r.AOR.Get(r.buf), r.Contact.Get(r.buf))
			}
		},
		)
	}
	*n = RegEntry{}       // DBG: zero it
	n.hashNo = ^uint32(0) // DBG: set invalid hash
	n.pos = 0
	n.buf = buf
	regESz := unsafe.Sizeof(*n)
	RegEntryAllocStats.TotalSize.Inc(uint(totalBufSize) + uint(regESz))
	if pNo < len(RegEntryAllocStats.Sizes) {
		RegEntryAllocStats.Sizes[pNo].Inc(1)
	} else {
		RegEntryAllocStats.Sizes[len(RegEntryAllocStats.Sizes)-1].Inc(1)
	}
	if int(regESz)/AllocRoundTo < len(RegEntryAllocStats.Sizes) {
		RegEntryAllocStats.Sizes[regESz/AllocRoundTo].Inc(1)
	} else {
		RegEntryAllocStats.Sizes[len(RegEntryAllocStats.Sizes)-1].Inc(1)
	}

	//DBG("AllocRegEntry(%d) => %p\n", bufSize, n)
	return n

}

// FreeRegEntry frees a RegEntry allocated with NewRegEntry.
func FreeRegEntry(e *RegEntry) {
	//DBG("FreeRegEntry(%p)\n", e)
	RegEntryAllocStats.FreeCalls.Inc(1)
	regEntrySize := unsafe.Sizeof(*e)
	totalBufSize := uintptr(cap(e.buf))
	if v := atomic.LoadInt32(&e.refCnt); v != 0 {
		log.Panicf("FreeRegEntry called for a referenced entry: %p ref: %d\n",
			e, e.refCnt)
	}
	if int(totalBufSize/AllocRoundTo) < len(poolBuffs) {
		poolBuffs[totalBufSize/AllocRoundTo].Put(unsafe.Pointer(&e.buf[0]))
	}
	e.buf = nil
	*e = RegEntry{}           // DBG: zero it to force crashes on re-use w/o alloc
	e.hashNo = ^uint32(0) - 1 // DBG: set invalid hash
	RegEntryAllocStats.TotalSize.Dec(uint(totalBufSize) + uint(regEntrySize))
	poolRegEntry.Put(e)
}
