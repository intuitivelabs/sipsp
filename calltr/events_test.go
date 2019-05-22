package calltr

import (
	"testing"
)

func TestEvTypeName(t *testing.T) {

	if len(evTypeName) != (int(EvBad) + 1) {
		t.Errorf("evTypeName[]: length mismatch %d/%d\n",
					len(evTypeName), int(EvBad) + 1)
	}
	for i, v := range evTypeName {
		if len(v) == 0 {
			t.Errorf("evTypeName[%d]: empty name\n", i)
		}
	}
}
