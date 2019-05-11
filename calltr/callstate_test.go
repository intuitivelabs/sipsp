package calltr

import (
	"testing"
)

func TestConvStateTimeoutS(t *testing.T) {
	if len(stateTimeoutS) != int(CallStNonInvFinished)+1 {
		t.Errorf("state to timeout conversion array size mismatch: %d / %d\n",
			len(stateTimeoutS), int(CallStNonInvFinished)+1)
	}
}

func TestConvStateString(t *testing.T) {
	if len(callSt2String) != int(CallStNonInvFinished)+1 {
		t.Errorf("state to string conversion array size mismatch: %d / %d\n",
			len(callSt2String), int(CallStNonInvFinished)+1)
	}
}
