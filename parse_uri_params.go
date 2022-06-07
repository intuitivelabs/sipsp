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
