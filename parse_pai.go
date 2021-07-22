// Copyright 2021 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipsp

import ()

type PPAIs struct {
	Vals     [2]PFromBody // parsed p-asserted-identities values (max 2)
	N        int          // no of PAI _values_ found, cab be > len(Vals)
	HNo      int          // no of different PAI _headers_ found
	LastHVal PField       // values part of the last PAI _header_ parsed
	last     PFromBody    // used if no space in Vals, as tmp state keeping
}

// VNo returns the number of parsed PAI values in c.Vals (0-2)
func (c *PPAIs) VNo() int {
	if c.N > len(c.Vals) {
		return len(c.Vals)
	}
	return c.N
}

// GetPAI returns the requested parsed PAI body or nil.
func (c *PPAIs) GetPAI(n int) *PFromBody {
	if c.VNo() > n {
		return &c.Vals[n]
	}
	return nil
}

// More returns true if there are more PAI values that did not fit in Vals.
func (c *PPAIs) More() bool {
	return c.N > len(c.Vals)
}

// Reset re-initializes the parsed values.
func (c *PPAIs) Reset() {
	*c = PPAIs{}
}

// Init initializes the PAI values.
func (c *PPAIs) Init() {
	c.Reset()
}

// Empty returns true if no PAI values have been parsed.
func (c *PPAIs) Empty() bool {
	return c.N == 0
}

// Parsed returns true if there are some parsed PAI values.
func (c *PPAIs) Parsed() bool {
	return c.N > 0
}

// ParseOnePAI parses the content of one PAI vale, found at
// offset offs in buf. pfrom will be filled with the parsed content.
// See ParseNameAddrPVal() for more information.
func ParseOnePAI(buf []byte, offs int, pfrom *PFromBody) (int, ErrorHdr) {
	next, err := ParseNameAddrPVal(HdrPAI, buf, offs, pfrom)
	// don't allow '*' as valid PAI value
	if (err == 0 || err == ErrHdrMoreValues) && pfrom.Star {
		err = ErrHdrValBad
	}
	return next, err
}

// ParseAllPAIValues tries to parse all the values in a PAI header
// situated at offs in buf and add them to the passed PPAIs.
// It can return ErrHdrMoreBytes if more data is needed (the value is not
// fully contained in buf).
func ParseAllPAIValues(buf []byte, offs int, c *PPAIs) (int, ErrorHdr) {
	var next int
	var err ErrorHdr
	var pf *PFromBody

	if c.N >= len(c.Vals) {
		if c.last.Parsed() {
			c.last.Reset()
		}
	}
	for {
		if c.N < len(c.Vals) {
			pf = &c.Vals[c.N]
		} else {
			pf = &c.last
		}
		next, err = ParseOnePAI(buf, offs, pf)
		switch err {
		case 0, ErrHdrMoreValues:
			if c.N == 0 {
				c.LastHVal = pf.V
			} else {
				c.LastHVal.Extend(int(pf.V.Offs + pf.V.Len))
			}
			c.N++ // next value, continue parsing
			if err == ErrHdrMoreValues {
				offs = next
				if pf == &c.last {
					c.last.Reset() // prepare for next value
				}
				continue // get next value
				// allow, but ignore more then  2 values
				// (to stop parsing if more then 2 values uncomment the following code)
			}
		/*
			 else if c.N > len(c.Vals) {
				err = ErrHdrTooManyVals
			}
		*/
		case ErrHdrMoreBytes:
			// do nothing, just for readability
		default:
			if pf == &c.last {
				c.last.Reset() // prepare for next value
			}
		}
		break
	}
	return next, err
}
