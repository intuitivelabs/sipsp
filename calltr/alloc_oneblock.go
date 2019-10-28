package calltr

import (
	"log"
	"reflect"
	"runtime"
	"sync/atomic"
	"unsafe"
)

// Alloc functions that try to allocate Entry and buffer(s) into one
// single contiguous memory block. Conditionally compiled.

// AllocCallEntry allocates a CallEntry and the CalLEntry.Key.buf in one block.
// The Key.buf will be keySize bytes length and info.buf infoSize.
// It might return nil if the memory limits are exceeded.
// Note: disabled for now, see AllocRegEntry_oneblock note about interaction
// with the GC.
func AllocCallEntry_oneblock(keySize, infoSize uint) *CallEntry {
	var e CallEntry
	CallEntryAllocStats.NewCalls.Inc(1)
	callEntrySize := uint(unsafe.Sizeof(e))
	totalSize := callEntrySize + keySize + infoSize
	totalSize = ((totalSize-1)/AllocRoundTo + 1) * AllocRoundTo // round up
	// TODO: use multiple of block-size blocks and pools for each block size
	buf := make([]byte, totalSize) //?allignment (seems to be always ok)
	/* alternative, forcing allignment, error checking skipped:

	abuf := make([]uint64, (totalSize-1)/unsafe.Sizeof(uint64(1)) +1)
	// make buf point to the same data as abuf:
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	slice.Data = uintptr(unsafe.Pointer(&abuf[0]))
	slice.Lne  = len(abuf)
	slice.Cap = cap(abuf)
	*/
	if buf == nil {
		CallEntryAllocStats.Failures.Inc(1)
		return nil
	}
	p := unsafe.Pointer(&buf[0])
	n := (*CallEntry)(p)
	// extra debugging: when about to be garbage collected, check if
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
	*n = e
	n.hashNo = ^uint32(0) // DBG: set invalid hash
	n.Key.Init(buf[callEntrySize:(callEntrySize + keySize)])
	n.Info.Init(buf[(callEntrySize + keySize):])
	CallEntryAllocStats.TotalSize.Inc(uint(totalSize))
	if int(totalSize)/AllocRoundTo < len(CallEntryAllocStats.Sizes) {
		CallEntryAllocStats.Sizes[totalSize/AllocRoundTo].Inc(1)
	} else {
		CallEntryAllocStats.Sizes[len(CallEntryAllocStats.Sizes)-1].Inc(1)
	}
	return n

}

// FreeCallEntry frees a CallEntry allocated with NewCallEntry.
func FreeCallEntry_oneblock(e *CallEntry) {
	CallEntryAllocStats.FreeCalls.Inc(1)
	callEntrySize := unsafe.Sizeof(*e)
	totalSize := callEntrySize + uintptr(cap(e.Key.buf))
	// sanity checks
	if totalSize > callEntrySize &&
		uintptr(unsafe.Pointer(e))+callEntrySize !=
			uintptr(unsafe.Pointer(&e.Key.buf[0])) {
		log.Panicf("FreeCallEntry called with call entry not allocated"+
			" with NewCallEntry: %p (sz: %x), buf %p\n",
			e, callEntrySize, &e.Key.buf[0])
	}
	if v := atomic.LoadInt32(&e.refCnt); v != 0 {
		log.Panicf("FreeCallEntry called for a referenced entry: %p ref: %d\n",
			e, e.refCnt)
	}
	*e = CallEntry{}          // DBG: zero it
	e.hashNo = ^uint32(0) - 1 // DBG: set invalid hash
	CallEntryAllocStats.TotalSize.Dec(uint(totalSize))
	// TODO: put it back in the corresp. pool
}

// AllocRegEntry allocates a RegEntry and the RegEntry.buf in one block.
// The RegEntry.buf will be bufSize bytes length.
// It might return nil if the memory limits are exceeded.
// Note: disabled for now, it looks like aliasing a []byte block via
// unsafe.Pointer to RegEntry* is not supported by the garbage collector and
// pointer inisde the RegEntry* alias are not taken into account when
// performin GC => RegEntry which are not at the list head appear as
// unreferenced (since they are ref'ed only from other RegEntry next & prev
// which are not seen by GC) => they might be freed "under us".
// Solution: use C.malloc() or custom malloc and make sure no pointer
// inside a RegEntry references any go alloc. stuff (since it won't be seen by GC).
func allocRegEntry_oneblock(bufSize uint) *RegEntry {
	var e RegEntry
	RegEntryAllocStats.NewCalls.Inc(1)
	regEntrySize := uint(unsafe.Sizeof(e))
	totalSize := regEntrySize + bufSize
	totalSize = ((totalSize-1)/AllocRoundTo + 1) * AllocRoundTo // round up
	// TODO: use multiple of block-size blocks and pools for each block size
	buf := make([]byte, totalSize) //?allignment (seems to be always ok)
	/* alternative, forcing allignment, error checking skipped:

	abuf := make([]uint64, (totalSize-1)/unsafe.Sizeof(uint64(1)) +1)
	// make buf point to the same data as abuf:
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	slice.Data = uintptr(unsafe.Pointer(&abuf[0]))
	slice.Lne  = len(abuf)
	slice.Cap = cap(abuf)
	*/
	if buf == nil {
		RegEntryAllocStats.Failures.Inc(1)
		return nil
	}
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	n := (*RegEntry)(unsafe.Pointer(slice.Data))
	//n := (*RegEntry)(unsafe.Pointer(&buf[0]))
	//runtime.SetFinalizer(n, func(p *RegEntry) { DBG("Finalizer RegEntry(%p)\n", p) })
	//runtime.SetFinalizer(&buf[0], func(p unsafe.Pointer) { DBG("Finalizer &buf[0](%p)\n", p) })
	//runtime.SetFinalizer(&buf, func(p *[]byte) { DBG("Finalizer buf[](%p)\n", p) })
	e.hashNo = ^uint32(0) // DBG: set invalid hash
	e.pos = 0
	//n := &e // quick HACK
	*n = e
	n.buf = buf[regEntrySize:]
	RegEntryAllocStats.TotalSize.Inc(uint(totalSize))
	if int(totalSize)/AllocRoundTo < len(RegEntryAllocStats.Sizes) {
		RegEntryAllocStats.Sizes[totalSize/AllocRoundTo].Inc(1)
	} else {
		RegEntryAllocStats.Sizes[len(RegEntryAllocStats.Sizes)-1].Inc(1)
	}
	DBG("AllocRegEntry(%d) => %p\n", bufSize, n)
	runtime.KeepAlive(buf)
	runtime.KeepAlive(slice.Data)
	return n

}

// FreeRegEntry frees a RegEntry allocated with NewRegEntry.
// disabled see AllocRegEntry_oneblock
func freeRegEntry_oneblock(e *RegEntry) {
	//DBG("FreeRegEntry(%p)\n", e)
	RegEntryAllocStats.FreeCalls.Inc(1)
	regEntrySize := unsafe.Sizeof(*e)
	totalSize := regEntrySize + uintptr(cap(e.buf))
	// sanity checks
	if totalSize > regEntrySize &&
		uintptr(unsafe.Pointer(e))+regEntrySize !=
			uintptr(unsafe.Pointer(&e.buf[0])) {
		log.Panicf("FreeRegEntry called with reg entry not allocated"+
			" with NewRegEntry: %p (sz: %x), buf %p\n",
			e, regEntrySize, &e.buf[0])
	}
	if v := atomic.LoadInt32(&e.refCnt); v != 0 {
		log.Panicf("FreeRegEntry called for a referenced entry: %p ref: %d\n",
			e, e.refCnt)
	}
	*e = RegEntry{}           // DBG: zero it to force crashes on re-use w/o alloc
	e.hashNo = ^uint32(0) - 1 // DBG: set invalid hash
	RegEntryAllocStats.TotalSize.Dec(uint(totalSize))
	// TODO: put it back in the corresp. pool
}
