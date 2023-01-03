// Copyright 2021 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

package sipsp

import (
	"bytes"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
)

func TestHexDigToI(t *testing.T) {
	for c := 0; c <= 255; c++ {
		res := hexDigToI(byte(c))
		s := string([]byte{byte(c)})
		n, err := strconv.ParseUint(s, 16, 64)
		if err != nil {
			// check for error
			if res >= 0 {
				t.Errorf("TextHexDigToI: expected failure for %q, got %d\n",
					s, res)
			}
		} else if n != uint64(res) {
			t.Errorf("TextHexDigToI: expected %d for %q, got %d\n", n, s, res)
		}
	}

}

func TestHexToURand(t *testing.T) {

	const loops = 100000
	var b bytes.Buffer

	for i := 0; i < loops; i++ {
		n := rand.Uint64()
		// lowercase
		fmt.Fprintf(&b, "%x", n)
		if res, ok := hexToU(b.Bytes()); !ok {
			t.Errorf("TestHexToURand: hexToU failed for %q -> (0x%x, %v)",
				b.Bytes(), res, ok)
		} else if res != n {
			t.Errorf("TestHexToURand: hexToU failed for %q ->"+
				" 0x%x != exp. 0x%x",
				b.Bytes(), res, n)
		}
		b.Reset()
		// uppercase
		fmt.Fprintf(&b, "%x", n)
		if res, ok := hexToU(b.Bytes()); !ok {
			t.Errorf("TestHexToURand: hexToU failed for %q -> (0x%x, %v)",
				b.Bytes(), res, ok)
		} else if res != n {
			t.Errorf("TestHexToURand: hexToU failed for %q ->"+
				" 0x%x != exp. 0x%x",
				b.Bytes(), res, n)
		}
		b.Reset()
	}
}

func TestHexToIRand(t *testing.T) {

	const loops = 1000000
	var b bytes.Buffer

	for i := 0; i < loops; i++ {
		n := rand.Int63()
		if rand.Intn(2) == 1 {
			n = -n
		}
		// lowercase
		fmt.Fprintf(&b, "%x", n)
		if res, ok := hexToI(b.Bytes()); !ok {
			t.Errorf("TestHexToIRand: hexToU failed for %q -> (0x%x, %v)",
				b.Bytes(), res, ok)
		} else if res != n {
			t.Errorf("TestHexToIRand: hexToU failed for %q ->"+
				" 0x%x != exp. 0x%x",
				b.Bytes(), res, n)
		}
		b.Reset()
		// uppercase
		fmt.Fprintf(&b, "%x", n)
		if res, ok := hexToI(b.Bytes()); !ok {
			t.Errorf("TestHexToIRand: hexToU failed for %q -> (0x%x, %v)",
				b.Bytes(), res, ok)
		} else if res != n {
			t.Errorf("TestHexToIRand: hexToU failed for %q ->"+
				" 0x%x != exp. 0x%x",
				b.Bytes(), res, n)
		}
		b.Reset()
	}
}
