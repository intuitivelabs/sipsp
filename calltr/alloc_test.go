package calltr

import (
	"math/rand"
	"testing"
	"unsafe"
)

func TestCallStateAlloc(t *testing.T) {

	var e *CallEntry = AllocCallEntry(10, 0)

	t.Logf("callstate %p, size %x &buf[0]= %v size %x\n",
		e, unsafe.Sizeof(*e), &e.Key.buf[0], len(e.Key.buf))
	i := 0
	for ; i < 1000000; i++ {
		sz := uint(rand.Intn(128))
		e = AllocCallEntry(sz, 0)
		if len(e.Key.buf) < int(sz) {
			t.Errorf("wrong buf size %d, expected at least %d\n",
				len(e.Key.buf), sz)
		}
		if len(e.Key.buf) != 0 &&
			uintptr(unsafe.Pointer(&(e.Key.buf[0]))) !=
				uintptr(unsafe.Pointer(e))+unsafe.Sizeof(*e) {
			t.Errorf("wrong buffer offset %p, e = %p , sizeof(e)=%x\n",
				&e.Key.buf[0], e, unsafe.Sizeof(*e))
		}
		for j := 0; j < len(e.Key.buf); j++ {
			e.Key.buf[j] = 0xff
		}
		// check beginning and end
		if e.next != nil || e.prev != nil ||
			e.refCnt != 0 {
			t.Errorf("corrupted call entry\n")
		}
		if uintptr(unsafe.Pointer(e))%unsafe.Alignof(*e) != 0 {
			t.Errorf("alignment error for e: %p not multiple of %d\n",
				e, unsafe.Alignof(*e))
		}
	}
	t.Logf("%d test runs\n", i)
}
