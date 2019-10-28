package calltr

import (
	"sync/atomic"
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
