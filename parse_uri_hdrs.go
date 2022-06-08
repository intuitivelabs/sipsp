// Copyright 2022 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

package sipsp

import (
	"github.com/intuitivelabs/bytescase"
)

// URIHdr is the type used or holding a parsed uri header
type URIHdr PTokParam

func (h *URIHdr) Reset() {
	(*PTokParam)(h).Reset()
}

// URIHdrsLst contains the parsed uri headers (?h1&h2&h3...)
type URIHdrsLst struct {
	Hdrs []URIHdr // parsed hdrs place holder (pre-alloc)
	N    int      // no of headers found, can be > len(Hdrs)

	tmp URIHdr // temporary saved parsing state (between calls)
}

// Reset re-initializes the parsed parameter list
func (l *URIHdrsLst) Reset() {
	for i := 0; i < l.HNo(); i++ {
		l.Hdrs[i].Reset()
	}
	t := l.Hdrs
	*l = URIHdrsLst{}
	l.Hdrs = t
}

// HNo returns the number of parsed headers.
func (l *URIHdrsLst) HNo() int {
	if l.N > len(l.Hdrs) {
		return len(l.Hdrs)
	}
	return l.N
}

// More returns true if there are more values that did not fit in []Hdrs.
func (l *URIHdrsLst) More() bool {
	return l.N > len(l.Hdrs)
}

// Init initializes the parsed headers list with a headers place-holder
// array.
func (l *URIHdrsLst) Init(hbuf []URIHdr) {
	l.Hdrs = hbuf
}

// Empty returns true if no uri headers have been parsed.
func (l *URIHdrsLst) Empty() bool {
	return l.N == 0
}

// ParseAllURIHdrs tries to parse buf[offs:] as a list of
// uri headers and add them to the passed URIHdrsLst.
// The flags parameter should be used to specify how the headers list
// is terminated: '?' (POptTokQmTermF), space (POptTokSpTermF) or end
// of string (POptInputEndF).
//
// The return values are: a new offset after the parsed value (that can be
// used to continue parsing), the number of header values parsed and an error.
// It can return ErrHdrMoreBytes if more data is needed (the value is not
// fully contained in buf).
// On success it returns either ErrHdrOk or ErrHdrEOH (ok & end of input
// reached).
func ParseAllURIHdrs(buf []byte, offs int, l *URIHdrsLst,
	flags POptFlags) (int, int, ErrorHdr) {
	flags |= POptParamAmpSepF | POptTokURIHdrF

	var next int
	var err ErrorHdr
	var h *URIHdr

	vNo := 0 // number of values parsed during the current call
	for {
		if l.N < len(l.Hdrs) {
			h = &l.Hdrs[l.N]
		} else {
			h = &l.tmp
		}
		next, err = ParseTokenParam(buf, offs, (*PTokParam)(h), flags)
		switch err {
		case 0, ErrHdrMoreValues, ErrHdrEOH:
			vNo++
			l.N++ // next value, continue parsing
			if h == &l.tmp {
				l.tmp.Reset() // prepare for the next value (cleanup state)
			}
			if err == ErrHdrMoreValues {
				offs = next
				continue // get next value
			}
		case ErrHdrMoreBytes:
			// do nothing -> exit
		default:
			h.Reset() // some error -> clear the current tmp state
		}
		break
	}
	return next, vNo, err
}

// URIHdrsLstEq returns true if 2 parsed uri headers lists are equal
// according  to rfc3261 19.1.4.
//
// Each URIHdrsLst is accompanied by its []byte buffer in which it points.
// Note: it doesn't handle duplicate header values that are present in only
//       one uri and it matches headers value as case insensitive strings.
func URIHdrsLstEq(
	l1 *URIHdrsLst, buf1 []byte,
	l2 *URIHdrsLst, buf2 []byte) bool {
	// any present uri header must be present in both URIs and must match.
	if l1.HNo() != l2.HNo() {
		// different number of header
		return false
	}
	for i := 0; i < l1.HNo(); i++ {
		found := false
		for j := 0; j < l2.HNo(); j++ {
			if bytescase.CmpEq(
				l1.Hdrs[i].Name.Get(buf1),
				l2.Hdrs[j].Name.Get(buf2)) {
				if !bytescase.CmpEq(l1.Hdrs[i].Val.Get(buf1),
					l2.Hdrs[j].Val.Get(buf2)) {
					// present in both, but values do not match
					break // continue trying, maybe there's another hdr with
					// the same name
				}
				found = true
				break
			}
		}
		if !found {
			// present only in the first
			return false
		}
	}
	return true
}

// URIHdrsEq will parse & compare 2 uri headers lists
func URIHdrsEq(
	buf1 []byte, offs1 int,
	buf2 []byte, offs2 int) (bool, ErrorHdr) {

	const flags = POptTokURIHdrF | POptInputEndF

	// temporary params lists
	// TODO: adapt size
	var hlst1, hlst2 URIHdrsLst
	var hbuf1, hbuf2 [100]URIHdr

	hlst1.Init(hbuf1[:])
	hlst2.Init(hbuf2[:])

	_, _, err1 := ParseAllURIHdrs(buf1, offs1, &hlst1, flags)
	if err1 != ErrHdrOk && err1 != ErrHdrEOH {
		return false, err1
	}
	_, _, err2 := ParseAllURIHdrs(buf2, offs2, &hlst2, flags)
	if err2 != ErrHdrOk && err2 != ErrHdrEOH {
		return false, err2
	}
	return URIHdrsLstEq(&hlst1, buf1, &hlst2, buf2), ErrHdrOk
}
