// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipsp

import (
//	"fmt"
)

// PContacts contains the parsed Contact header values for one or more
// different Contact headers (all the contacts in the message that fit
// in the parsed value array).
type PContacts struct {
	Vals       []PFromBody // parsed contacts min(N, len(Vals))
	N          int         // no of contact _values_ found, can be >len(Vals)
	HNo        int         // no of different Contact: _headers_ found
	MaxExpires uint32
	MinExpires uint32
	LastHVal   PField    // value part of the last contact _header_ parsed
	last       PFromBody // used if no space in Vals, for keeping state
	first      PFromBody // even if Vals is nil, we remember the first val.
}

// VNo returns the number of parsed contacts headers.
func (c *PContacts) VNo() int {
	if c.N > len(c.Vals) {
		return len(c.Vals)
	}
	return c.N
}

// GetContact returns the requested parsed contact body or nil.
func (c *PContacts) GetContact(n int) *PFromBody {
	if c.VNo() > n {
		return &c.Vals[n]
	}
	if c.Empty() {
		return nil
	}
	if c.N == (n + 1) {
		return &c.last
	}
	if n == 0 {
		return &c.first
	}
	return nil
}

// More returns true if there are more contacts that did not fit in Vals.
func (c *PContacts) More() bool {
	return c.N > len(c.Vals)
}

// Reset re-initializes the parsed values.
func (c *PContacts) Reset() {
	for i := 0; i < c.VNo(); i++ {
		c.Vals[i].Reset()
	}
	v := c.Vals
	*c = PContacts{}
	c.Vals = v
}

// Init initializes the contact values from an array of parsed values.
func (c *PContacts) Init(valbuf []PFromBody) {
	c.Vals = valbuf
}

// Empty returns true if no contacts values have been parsed.
func (c *PContacts) Empty() bool {
	return c.N == 0
}

// Parsed returns true if there are some parsed contacts values.
func (c *PContacts) Parsed() bool {
	return c.N > 0
}

// ParseOneContact parses the content of one Contact vale, found at
// offset offs in buf. pfrom will be filled with the parsed content.
// See ParseNameAddrPVal() for more information.
func ParseOneContact(buf []byte, offs int, pfrom *PFromBody) (int, ErrorHdr) {
	return ParseNameAddrPVal(HdrContact, buf, offs, pfrom)
}

// ParseAllContactValues tries to parse all the values in a contact header
// situated at offs in buf and add them to the passed PContacts.
// It can return ErrHdrMoreBytes if more data is needed (the value is not
// fully contained in buf).
func ParseAllContactValues(buf []byte, offs int, c *PContacts) (int, ErrorHdr) {
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
		next, err = ParseOneContact(buf, offs, pf)
		/*
			fmt.Printf("ParseOneContact(%q, (%d), %p) -> %d, %q  rest %q\n",
				buf[offs:], offs, pf, next, err, buf[next:])
		*/
		switch err {
		case 0, ErrHdrMoreValues:
			if c.N == 0 {
				c.LastHVal = pf.V
				c.MinExpires = ^uint32(0)
			} else {
				c.LastHVal.Extend(int(pf.V.Offs + pf.V.Len))
			}
			c.N++ // next value, continue parsing
			if c.MaxExpires < pf.Expires {
				c.MaxExpires = pf.Expires
			}
			if c.MinExpires > pf.Expires {
				c.MinExpires = pf.Expires
			}
			if c.N == 1 && len(c.Vals) == 0 {
				c.first = *pf //set c.first
			}
			if err == ErrHdrMoreValues {
				offs = next
				if pf == &c.last {
					c.last.Reset() // prepare for next value
				}
				continue // get next value
			}
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
