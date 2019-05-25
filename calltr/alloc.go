package calltr

import (
	"log"
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

// AllocCallEtrny allocates a CallEntry and the CalLEntry.Key.buf in one block.
// The Key.buf will be keySize bytes length and info.buf infoSize.
// It might return nil if the memory limits are exceeded.
func AllocCallEntry(keySize, infoSize uint) *CallEntry {
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
	*n = e
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
func FreeCallEntry(e *CallEntry) {
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
	CallEntryAllocStats.TotalSize.Dec(uint(totalSize))
	// TODO: put it back in the corresp. pool
}
