package sipsp

import (
	"bytes"

	"andrei/sipsp/bytescase"
)

type SIPMethod uint8

// method types
const (
	MUndef SIPMethod = iota
	MRegister
	MInvite
	MAck
	MBye
	MPrack
	MCancel
	MOptions
	MSubscribe
	MNotify
	MUpdate
	MInfo
	MRefer
	MPublish
	MMessage
	MOther // last
)

var Method2Name [MOther + 1][]byte = [MOther + 1][]byte{
	MUndef:     []byte(""),
	MInvite:    []byte("INVITE"),
	MAck:       []byte("ACK"),
	MBye:       []byte("BYE"),
	MCancel:    []byte("CANCEL"),
	MRegister:  []byte("REGISTER"),
	MPrack:     []byte("PRACK"),
	MOptions:   []byte("OPTIONS"),
	MUpdate:    []byte("UPDATE"),
	MSubscribe: []byte("SUBSCRIBE"),
	MNotify:    []byte("NOTIFY"),
	MInfo:      []byte("INFO"),
	MRefer:     []byte("REFER"),
	MPublish:   []byte("PUBLISH"),
	MMessage:   []byte("MESSAGE"),
	MOther:     []byte("OTHER"),
}

func (m SIPMethod) Name() []byte {
	if m > MOther {
		return Method2Name[MUndef]
	}
	return Method2Name[m]
}

// debug/ pretty print
func (m SIPMethod) String() string {
	return string(m.Name())
}

func GetMethodNo(buf []byte) SIPMethod {
	i := hashMthName(buf)
	for _, m := range mthNameLookup[i] {
		if bytes.Equal(buf, m.n) {
			return m.t
		}
	}
	//TODO: make it more efficient
	/*
		for i := MUndef + 1; i < MOther; i++ {
			if bytes.Equal(buf, Method2Name[i]) {
				return i
			}
		}
	*/
	return MOther
}

// magic values: after adding/removing methods run tests again
// looking for max. elem per bucket == 1 for minimum hash size
const (
	mthBitsLen   uint = 2 //re-run tests after changing
	mthBitsFChar uint = 3
)

type mth2Type struct {
	n []byte
	t SIPMethod
}

var mthNameLookup [1 << (mthBitsLen + mthBitsFChar)][]mth2Type

func hashMthName(n []byte) int {
	const (
		mC = (1 << mthBitsFChar) - 1
		mL = (1 << mthBitsLen) - 1
	)
	return (int(bytescase.ByteToLower(n[0])) & mC) |
		((len(n) & mL) << mthBitsFChar)
}

func init() {
	// init lookup method-to-type array
	for i := MUndef + 1; i < MOther; i++ {
		h := hashMthName(Method2Name[i])
		mthNameLookup[h] =
			append(mthNameLookup[h], mth2Type{Method2Name[i], i})
	}
}
