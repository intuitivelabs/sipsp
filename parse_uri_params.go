// Copyright 2022 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

package sipsp

import (
	"github.com/intuitivelabs/bytescase"
)

// URIParamF is the type used for the known uri parameters converted to
// a "flags" numeric value (values are 2^k)
type URIParamF uint

// URI parameters flags values

const URIParamNone URIParamF = 0 // not "parsed"
const (
	URIParamTransportF URIParamF = 1 << iota
	URIParamUserF
	URIParamMethodF
	URIParamTTLF
	URIParamMaddrF
	URIParamLRF
	URIParamOtherF // unknown/other
)

// URIParamResolve will try to resolve/parse a uri parameter value to
// the correponding numeric URIParamF flag.
func URIParamResolve(n []byte) URIParamF {
	switch len(n) {
	case 9:
		if bytescase.CmpEq(n, []byte("transport")) {
			return URIParamTransportF
		}
	case 2:
		if bytescase.CmpEq(n, []byte("lr")) {
			return URIParamLRF
		}
	case 5:
		if bytescase.CmpEq(n, []byte("maddr")) {
			return URIParamMaddrF
		}
	case 4:
		if bytescase.CmpEq(n, []byte("user")) {
			return URIParamUserF
		}
	case 6:
		if bytescase.CmpEq(n, []byte("method")) {
			return URIParamMethodF
		}
	case 3:
		if bytescase.CmpEq(n, []byte("ttl")) {
			return URIParamTTLF
		}
	}
	return URIParamOtherF
}

// URIParam contains a parsed uri param and the correponding numeric type.
type URIParam struct {
	Param PTokParam // whole param broken into id and value
	T     URIParamF // type  flag
}

// Reset re-initializes an URIParam.
func (p *URIParam) Reset() {
	p.Param.Reset()
	p.T = URIParamNone
}

// URIParamsLst contains the parsed uri parameters.
type URIParamsLst struct {
	Params []URIParam // parsed params, pre-alloc
	N      int        // no of params found, can be > len(Params)
	Types  URIParamF  // all the param types found, concatenated

	tmp URIParam // temporary saved parsing state (between calls)
}

// Reset re-initializes the parsed parameter list
func (l *URIParamsLst) Reset() {
	for i := 0; i < l.PNo(); i++ {
		l.Params[i].Reset()
	}
	t := l.Params
	*l = URIParamsLst{}
	l.Params = t
}

// PNo returns the number of parsed parameters.
func (l *URIParamsLst) PNo() int {
	if l.N > len(l.Params) {
		return len(l.Params)
	}
	return l.N
}

// More returns true if there are more values that did not fit in Vals.
func (l *URIParamsLst) More() bool {
	return l.N > len(l.Params)
}

// Init initializes the parsed paramters list with a parameter place-holder
// array.
func (l *URIParamsLst) Init(pbuf []URIParam) {
	l.Params = pbuf
}

// Empty returns true if no parameters have been parsed.
func (l *URIParamsLst) Empty() bool {
	return l.N == 0
}

// ParseAllURIParams tries to parse buf[offs:] as a list of
// uri parameters and add them to the passed URIParamsLst.
// The flags parameter should be used to specify how the parameters list
// is terminated: '?' (POptTokQmTermF), space (POptTokSpTermF) or end
// of string (POptInputEndF).
//
// The return values are: a new offset after the parsed value (that can be
// used to continue parsing), the number of header values parsed and an error.
// It can return ErrHdrMoreBytes if more data is needed (the value is not
// fully contained in buf).
func ParseAllURIParams(buf []byte, offs int, l *URIParamsLst,
	flags POptFlags) (int, int, ErrorHdr) {
	flags |= POptParamSemiSepF

	var next int
	var err ErrorHdr
	var p *URIParam

	vNo := 0 // number of values parsed during the current call
	for {
		if l.N < len(l.Params) {
			p = &l.Params[l.N]
		} else {
			p = &l.tmp
		}
		next, err = ParseTokenParam(buf, offs, &p.Param, flags)
		switch err {
		case 0, ErrHdrMoreValues, ErrHdrEOH:
			p.T = URIParamResolve(p.Param.Name.Get(buf))
			l.Types |= p.T
			vNo++
			l.N++ // next value, continue parsing
			if p == &l.tmp {
				l.tmp.Reset() // prepare for the next value (cleanup state)
			}
			if err == ErrHdrMoreValues {
				offs = next
				continue // get next value
			}
		case ErrHdrMoreBytes:
			// do nothing -> exit
		default:
			p.Reset() // some error -> clear the current tmp state
		}
		break
	}
	return next, vNo, err
}

// URIParamsLstEq returns true if 2 parsed uri parameters lists are equal
// according  to rfc3261 19.1.4.
//
// Each URIParamLst is accompanied by its []byte buffer in which it points.
func URIParamsLstEq(
	l1 *URIParamsLst, buf1 []byte,
	l2 *URIParamsLst, buf2 []byte) bool {

	const bmask = URIParamUserF | URIParamTTLF | URIParamMethodF |
		URIParamMaddrF

	// user, ttl, method & maddr that appear in only one uri, never
	// match
	if (l1.Types & bmask) != (l2.Types & bmask) {
		return false
	}
	// slow matching: if a parameter is present in both uris, it must match,
	//               all other appearing in only one uri
	//               (not in bmask above) are ignored
	for i := 0; i < l1.PNo(); i++ {
		for j := 0; j < l2.PNo(); j++ {
			if l1.Params[i].T == l2.Params[j].T &&
				(l1.Params[i].T != URIParamOtherF ||
					bytescase.CmpEq(l1.Params[i].Param.Name.Get(buf1),
						l2.Params[j].Param.Name.Get(buf2))) {
				if !bytescase.CmpEq(l1.Params[i].Param.Val.Get(buf1),
					l2.Params[j].Param.Val.Get(buf2)) {
					return false
				}
				break
			}
		}
	}
	return true
}

// URIParamsEq will parse & compare a uri parameteres list
func URIParamsEq(
	buf1 []byte, offs1 int,
	buf2 []byte, offs2 int) (bool, ErrorHdr) {

	const flags = POptTokURIParamF | POptInputEndF

	// temporary params lists
	// TODO: adapt size
	var plst1, plst2 URIParamsLst
	var pbuf1, pbuf2 [100]URIParam

	plst1.Init(pbuf1[:])
	plst2.Init(pbuf2[:])

	_, _, err1 := ParseAllURIParams(buf1, offs1, &plst1, flags)
	if err1 != ErrHdrOk && err1 != ErrHdrEOH {
		return false, err1
	}
	_, _, err2 := ParseAllURIParams(buf2, offs2, &plst2, flags)
	if err2 != ErrHdrOk && err2 != ErrHdrEOH {
		return false, err2
	}
	return URIParamsLstEq(&plst1, buf1, &plst2, buf2), ErrHdrOk
}
