package calltr

import (
	"testing"
	"unsafe"
)

func TestEvTypeName(t *testing.T) {

	if len(evTypeName) != (int(EvBad) + 1) {
		t.Errorf("evTypeName[]: length mismatch %d/%d\n",
			len(evTypeName), int(EvBad)+1)
	}
	for i, v := range evTypeName {
		if len(v) == 0 {
			t.Errorf("evTypeName[%d]: empty name\n", i)
		}
	}
}

func TestEvFlags(t *testing.T) {
	var f EventFlags
	if unsafe.Sizeof(f)*8 < uintptr(EvBad) {
		t.Errorf("EventFlags: flags type too small: %d bits but %d needed\n",
			unsafe.Sizeof(f)*8, EvBad)
	}
	for e := EvNone; e < EvBad; e++ {
		if f.Set(e) {
			t.Errorf("EventFlags.Set(%v): wrong return\n", e)
		}
		if !f.Test(e) {
			t.Errorf("EventFlags.Test(%v): wrong return\n", e)
		}
	}
	for e := EvNone; e < EvBad; e++ {
		if !f.Test(e) {
			t.Errorf("EventFlags.Test(%v): wrong return\n", e)
		}
		if !f.Clear(e) {
			t.Errorf("EventFlags.Clear(%v): wrong return\n", e)
		}
		if f.Test(e) {
			t.Errorf("EventFlags.Test(%v): wrong return\n", e)
		}
	}
}
