package calltr

import (
	"log"
	"runtime"
	"sync/atomic"
	"unsafe"
)

const AllocRoundTo = 8

type StatCounter uint64

func (c *StatCounter) Inc(v uint) uint64 {
	return atomic.AddUint64((*uint64)(c), uint64(v))
}

func (c *StatCounter) Dec(v uint) uint64 {
	return atomic.AddUint64((*uint64)(c), ^uint64(v-1))
}

func (c *StatCounter) Get(v uint) uint64 {
	return atomic.LoadUint64((*uint64)(c))
}

type AllocStats struct {
	TotalSize StatCounter
	NewCalls  StatCounter
	FreeCalls StatCounter
	Failures  StatCounter
	Sizes     [1024]StatCounter
}

var CallEntryAllocStats AllocStats
var RegEntryAllocStats AllocStats

// AllocCallEntry allocates a CallEntry and the CalLEntry.Key.buf in one block.
// The Key.buf will be keySize bytes length and info.buf infoSize.
// It might return nil if the memory limits are exceeded.
// Note: this version allocates a separate CallEntry and buffer which is not
// optimal performance wise.
func AllocCallEntry(keySize, infoSize uint) *CallEntry {
	var n *CallEntry
	CallEntryAllocStats.NewCalls.Inc(1)
	callEntrySize := uint(unsafe.Sizeof(*n))
	totalBufSize := keySize + infoSize
	totalBufSize = ((totalBufSize-1)/AllocRoundTo + 1) * AllocRoundTo //round up
	// TODO: use multiple of block-size blocks and pools for each block size
	buf := make([]byte, totalBufSize)
	if buf == nil {
		CallEntryAllocStats.Failures.Inc(1)
		return nil
	}
	n = new(CallEntry)
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
	n.hashNo = ^uint32(0) // DBG: set invalid hash
	n.Key.Init(buf[:keySize])
	n.Info.Init(buf[keySize:])
	CallEntryAllocStats.TotalSize.Inc(uint(totalBufSize + callEntrySize))
	if int(totalBufSize)/AllocRoundTo < len(CallEntryAllocStats.Sizes) {
		CallEntryAllocStats.Sizes[totalBufSize/AllocRoundTo].Inc(1)
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
	e.Key.buf = nil
	e.Info.buf = nil
	*e = CallEntry{}          // DBG: zero everything
	e.hashNo = ^uint32(0) - 1 // DBG: set invalid hash (mark as free'd)
	CallEntryAllocStats.TotalSize.Dec(uint(totalBufSize) + uint(callEntrySize))
}

// AllocRegEntry allocates a RegEntry and the RegEntry.buf.
// The RegEntry.buf will be bufSize bytes length.
// It might return nil if the memory limits are exceeded.
func AllocRegEntry(bufSize uint) *RegEntry {
	var e RegEntry
	RegEntryAllocStats.NewCalls.Inc(1)
	totalSize := bufSize
	totalSize = ((totalSize-1)/AllocRoundTo + 1) * AllocRoundTo // round up
	// TODO: use multiple of block-size blocks and pools for each block size
	buf := make([]byte, totalSize) //?allignment (seems to be always ok)
	if buf == nil {
		RegEntryAllocStats.Failures.Inc(1)
		return nil
	}
	e.hashNo = ^uint32(0) // DBG: set invalid hash
	e.pos = 0
	e.buf = buf
	n := &e // quick HACK
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
	regESz := unsafe.Sizeof(*n)
	RegEntryAllocStats.TotalSize.Inc(uint(totalSize) + uint(regESz))
	if int(totalSize)/AllocRoundTo < len(RegEntryAllocStats.Sizes) {
		RegEntryAllocStats.Sizes[totalSize/AllocRoundTo].Inc(1)
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
	totalSize := regEntrySize + uintptr(cap(e.buf))
	if v := atomic.LoadInt32(&e.refCnt); v != 0 {
		log.Panicf("FreeRegEntry called for a referenced entry: %p ref: %d\n",
			e, e.refCnt)
	}
	e.buf = nil
	*e = RegEntry{}           // DBG: zero it to force crashes on re-use w/o alloc
	e.hashNo = ^uint32(0) - 1 // DBG: set invalid hash
	RegEntryAllocStats.TotalSize.Dec(uint(totalSize))
	// TODO: put it back in the corresp. pool
}
