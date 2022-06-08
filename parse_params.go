// Copyright 2022 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

// Code originally from intuitivelabs/https/parse_tok.go.

package sipsp

import ()

// PTokParam contains a parameter (from a ';' separated name=val list)
// E.g. p1=v1;p2=v2 => PTokParam will contain the parsed "p1=v1" part and
// another call to ParseTokenParam will return "p2=v2".
type PTokParam struct {
	All   PField // complete parameter field ( name = value), e.g.: "p1=v1"
	Name  PField // param. name with stripped whitespace (e.g. "p1")
	Val   PField // param value with stripped whitespace (e.g. "v1")
	state uint8  // internal state
}

func (pt *PTokParam) Reset() {
	*pt = PTokParam{}
}

func (pt *PTokParam) Empty() bool {
	return pt.All.Empty()
}

// SkipQuoted skips a quoted string, looking for the end quote.
// It handles escapes. It expects to be called with an offset pointing
// _inside_ some open quotes (after the '"' character).
// On success it returns and offset after the closing quote.
// If there are not enough bytes to find the end, it will return
// ErrHdrMoreBytes and an offset (which can be used to continue parsing after
// more bytes have been added to buf).
// It doesn't allow CR or LF inside the quoted string (see rfc7230 3.2.6).
func SkipQuoted(buf []byte, offs int) (int, ErrorHdr) {
	i := offs
	// var n, crl int // next non lws and crlf length
	// var err, retOkErr ErrorHdr

	for i < len(buf) {
		c := buf[i]
		switch c {
		case '"':
			return i + 1, ErrHdrOk
		case '\\': // quoted-pair
			if (i + 1) < len(buf) {
				if buf[i+1] == '\r' || buf[i+1] == '\n' {
					// CR or LF not allowed in escape pairs
					return i + 1, ErrHdrBadChar
				}
				i += 2 // skip '\x'
				continue
			}
			goto moreBytes

			// -- don't allow \n or \r in quotes (see rfc 7230 3.2.6)
		case '\n', '\r', 0x7f:
			return i, ErrHdrBadChar
		default:
			if c < 0x21 && c != ' ' && c != '\t' {
				return i, ErrHdrBadChar
			}
			/*
				case ' ', '\t', '\n', '\r':
					n, crl, err = skipLWS(buf, i, flags)
					if err == 0 {
						i = n
						continue
					}
					if err == ErrHdrEOH {
						goto endOfHdr
					}
					if err == ErrHdrMoreBytes {
						i = n
						goto moreBytes
					}
					return n, err
			*/
		}
		i++
	}
moreBytes:
	return i, ErrHdrMoreBytes
	/*
		endOfHdr: // end of header found
			// here i will point to first WS char (including CR & LF)
			//      n will point to the line end (CR or LF)
			//      crl will contain the line end length (1 or 2) so that
			//      n+crl is the first char in the new header
			// unexpected end inside quotes !
			return n + crl, ErrHdrBad
	*/
}

// returns true if c is an allowed ascii char inside a token name or value
func tokAllowedChar(c byte, flags POptFlags) bool {
	if c <= 32 || c >= 127 {
		// no ctrl chars,  non visible chars or white space allowed
		// (see rfc7230 3.2.6)
		return false
	}
	// valid chars (rfc3261 25.1): alpha | digit | escaped (% hex hex) |
	//     "-" , "_",  ".",  "!", "~", "*", "'", "(", ")"
	if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') {
		return true
	}
	switch c {
	// unreserved marks + escape (%)
	case '-', '_', '.', '!', '~', '*', '\'', '(', ')', '%':
		return true

	// more valid chars for
	// params:    "[", "]", "/",    "&",    ":", "+", "$"
	// headers:   "[", "]", "/",    "?",    ":", "+", "$"
	case '[', ']', '/', ':', '+', '$':
		return true
	case '&':
		if flags&POptTokURIParamF != 0 {
			return true // if param
		}
		return false
	case '?':
		if flags&POptTokURIParamF != 0 {
			return false // if param, false
		}
		return true // if uri header part
	}
	return false
}

// ParseTokenParam will parse a string of the form param [= value] [;] .
// param has to be a valid token. value can be a token or a quoted string.
// White space is allowed before and after "=".
// The value part might be missing (e.g. ";lr").
// The string is also terminated by a token list separator
// (either ',' , whitespace after value and with no ';' or both, depending
// on the flags), in which case the returned offset will be the separator
// offset.
// If there are more parameters present (';' separated), the returned offset
// will be the start of the next parameter (after ';' and possible whitespace)
// and the returned error will be ErrHdrMoreValues.
// Return values:
//  - offs, ErrHdrOk - parsed full param and this is the last parameter. offs is // the offset of the next token separator or past the end of the buffer.
//  - offs. ErrHdrEOH - parsed full param and encountered end of header
//  (\r\nX). offs points at the first char after the end of header or past
//   the end of buffer.
// - offs, ErrHdrMoreValues - parsed full param and there are more values.
// offs is the start offset of the next parameter (leading white space trimmed)
// - offs, ErrHdrEmpty - empty parameter
// - offs. ErrHdrMoreBytes - more bytes are needed to finish parsing. offs
//  can be used to resume parsing (along with the same param).
// - any other ErrorHdr value -> parsing error and the offset of the 1st
// offending char.
func ParseTokenParam(buf []byte, offs int, param *PTokParam,
	flags POptFlags) (int, ErrorHdr) {

	sep := byte(';') // default
	term := byte(0)  // default end of params char (0 == none)
	if flags&(POptParamAmpSepF|POptTokURIHdrF) != 0 {
		sep = byte('&')
	} else if flags&(POptParamSemiSepF|POptTokURIParamF) != 0 {
		sep = byte(';')
	}

	if flags&(POptTokQmTermF|POptTokURIParamF) != 0 {
		term = byte('?')
	} else if flags&POptTokCommaTermF != 0 {
		term = byte(',')
	} else if flags&POptTokSpTermF != 0 {
		term = byte(0) // space term is handled differently
	}

	// internal state
	const (
		paramInit uint8 = iota
		paramName
		paramFEq
		paramFVal
		paramVal
		paramFSep
		paramFNxt
		paramInitNxtVal // more for nice debugging
		paramQuotedVal
		paramERR
		paramFIN
	)

	if param.state == paramFIN {
		// called again after finishing
		return offs, 0
	}
	i := offs
	var n, crl int // next non lws and crlf length
	var err, retOkErr ErrorHdr

	// valid chars: alpha | digit | escaped (% hex hex) |
	// mark:    "-" , "_",  ".",  "!", "~", "*", "'", "(", ")"

	// reserved: ";", "?", "/", ":", "@", "&", "=", "+", "$", ","
	// param-unreserved: "[", "]", "/",    "&",    ":", "+", "$"
	// hdr-unreserved:   "[", "]", "/",    "?",    ":", "+", "$"
	for i < len(buf) {
		c := buf[i]
		n = 0
		switch param.state {
		case paramInit, paramInitNxtVal, paramFNxt:
			switch c {
			case ' ', '\t', '\n', '\r':
				n, crl, err = skipLWS(buf, i, flags)
				if err == ErrHdrMoreBytes {
					// keep state and keep the offset pointing before the
					// whitespace
					goto moreBytes
				}
				// keep state
				if err == 0 {
					i = n
					continue
				}
				if err == ErrHdrEOH {
					goto endOfHdr
				}
				return n, err

			/* allowed chars handled in tokAllowedChar()
			case '/', ':', '@', '=', "+", "$", ",":
				// param name starts with un-allowed char
				param.state = paramERR
				return i, ErrHdrBadChar
			*/
			default:
				if c == sep {
					// do nothing, allow empty params, just skip them
					break
				}
				if !tokAllowedChar(c, flags) {
					param.state = paramERR
					return i, ErrHdrBadChar
				}
				if param.state == paramFNxt {
					goto moreValues
				}
				param.state = paramName
				param.Name.Set(i, i)
				param.All.Set(i, i)
			}
		case paramName:
			switch c {
			case ' ', '\t', '\n', '\r':
				n, crl, err = skipLWS(buf, i, flags)
				if err == ErrHdrMoreBytes {
					// keep state and keep the offset pointing before the
					// whitespace
					goto moreBytes
				}
				param.state = paramFEq
				param.Name.Extend(i)
				param.All.Extend(i)
				if err == 0 {
					i = n
					continue
				}
				if err == ErrHdrEOH {
					goto endOfHdr
				}
				return n, err
			case '=':
				param.Name.Extend(i)
				param.All.Extend(i + 1)
				param.state = paramFVal
			default:
				if c == term && term != 0 {
					param.Name.Extend(i)
					param.All.Extend(i)
					param.state = paramFIN
					return i, ErrHdrOk
				}
				if c == sep {
					// param with no value found, allow
					param.Name.Extend(i)
					param.All.Extend(i)
					param.state = paramFNxt
					break
				}
				if !tokAllowedChar(c, flags) {
					param.state = paramERR
					return i, ErrHdrBadChar
				}
				// do nothing
			}
		case paramFEq: // look for '=' | sep |','
			switch c {
			case ' ', '\t', '\n', '\r':
				n, crl, err = skipLWS(buf, i, flags)
				if err == ErrHdrMoreBytes {
					// keep state and keep the offset pointing before the
					// whitespace
					goto moreBytes
				}
				// keep state
				if err == 0 {
					i = n
					continue
				}
				if err == ErrHdrEOH {
					goto endOfHdr
				}
				return n, err
			case '=':
				param.state = paramFVal
			default:
				if c == term && term != 0 {
					param.state = paramFIN
					return i, ErrHdrOk
				}
				if c == sep {
					// param with no value found, allow
					param.state = paramFNxt
					break
				}
				if !tokAllowedChar(c, flags) {
					param.state = paramERR
					return i, ErrHdrBadChar
				}
				if flags&POptTokSpTermF != 0 {
					// found new space separated token after param name
					// e.g.: foo;p1 bar => consider bar new param
					param.state = paramFIN
					// return separator pos (as expected)
					if i >= offs+1 {
						return i - 1, ErrHdrOk
					} else {
						return i, ErrHdrOk
					}
				}
				// looking for '=' or sep, but found another token => error
				param.state = paramERR
				return i, ErrHdrBadChar
			}
		case paramFVal:
			switch c {
			case ' ', '\t', '\n', '\r':
				n, crl, err = skipLWS(buf, i, flags)
				if err == ErrHdrMoreBytes {
					// keep state and keep the offset pointing before the
					// whitespace
					goto moreBytes
				}
				// keep state
				if err == 0 {
					i = n
					continue
				}
				if err == ErrHdrEOH {
					goto endOfHdr
				}
				return n, err
			case '"':
				param.Val.Set(i, i)
				param.All.Extend(i)
				param.state = paramQuotedVal

			default:
				if c == term && term != 0 {
					// empty val (allow)
					param.Val.Set(i, i)
					param.state = paramFIN
					return i, ErrHdrOk
				}
				if c == sep {
					// empty val (allow)
					param.Val.Set(i, i)
					param.All.Extend(i)
					param.state = paramFNxt
					break
				}
				if !tokAllowedChar(c, flags) {
					param.state = paramERR
					return i, ErrHdrBadChar
				}
				param.state = paramVal
				param.Val.Set(i, i)
				param.All.Extend(i)
			}
		case paramVal:
			switch c {
			case ' ', '\t', '\n', '\r':
				n, crl, err = skipLWS(buf, i, flags)
				if err == ErrHdrMoreBytes {
					// keep state and keep the offset pointing before the
					// whitespace
					goto moreBytes
				}
				param.state = paramFSep
				param.Val.Extend(i)
				param.All.Extend(i)
				if err == 0 {
					i = n
					continue
				}
				if err == ErrHdrEOH {
					goto endOfHdr
				}
				return n, err
			default:
				if c == term && term != 0 {
					// empty val (allow)
					param.Val.Extend(i)
					param.All.Extend(i)
					param.state = paramFIN
					return i, ErrHdrOk
				}
				if c == sep {
					// empty val (allow)
					param.Val.Extend(i)
					param.All.Extend(i)
					param.state = paramFNxt
					break
				}
				if !tokAllowedChar(c, flags) {
					param.state = paramERR
					return i, ErrHdrBadChar
				}
			}
		case paramQuotedVal:
			n, err = SkipQuoted(buf, i)
			if err == ErrHdrMoreBytes {
				// keep state
				i = n
				goto moreBytes
			}
			if err == 0 {
				i = n
				param.Val.Extend(i)
				param.All.Extend(i)
				param.state = paramFSep
				continue
			}
			if err == ErrHdrEOH {
				goto endOfHdr
			}
			return n, err
		case paramFSep: // look for sep | ',' |' ' tok   after param value
			switch c {
			case ' ', '\t', '\n', '\r':
				n, crl, err = skipLWS(buf, i, flags)
				if err == ErrHdrMoreBytes {
					// keep state and keep the offset pointing before the
					// whitespace
					goto moreBytes
				}
				// keep state
				if err == 0 {
					i = n
					continue
				}
				if err == ErrHdrEOH {
					goto endOfHdr
				}
				return n, err
			default:
				if c == term && term != 0 {
					param.state = paramFIN
					return i, ErrHdrOk
				}
				if c == sep {
					param.state = paramFNxt
					break
				}
				if !tokAllowedChar(c, flags) {
					param.state = paramERR
					return i, ErrHdrBadChar
				}
				if flags&POptTokSpTermF != 0 {
					// found new space separated token after param value
					// e.g.: foo;p1=5 bar =>  consider bar new param
					param.state = paramFIN
					// return separator pos (as expected)
					if i >= offs+1 {
						return i - 1, ErrHdrOk
					} else {
						return i, ErrHdrOk
					}
				}
				// looking for '=' or sep, but found another token => error
				param.state = paramERR
				return i, ErrHdrBadChar
			}
		}
		i++
	}
moreBytes:
	// end of buffer, but couldn't find end of headers
	// i == len(buf) or
	// i = first space before the end & n == ( len(buf) or  position of
	//  last \n or \r before end of buf -- len(buf) -1)
	if flags&POptInputEndF != 0 { // end of input - force end of headers
		switch param.state {
		case paramInit, paramInitNxtVal, paramFNxt, paramFSep,
			paramFVal, paramFEq:
			// do nothing
		case paramName:
			// end while parsing param name => param w/o value
			param.Name.Extend(i)
			param.All.Extend(i)
		case paramVal:
			param.Val.Extend(i)
			param.All.Extend(i)
		case paramQuotedVal:
			// error, open quote
			return i, ErrHdrMoreBytes
		default:
			return i, ErrHdrBug
		}
		crl = 0
		n = len(buf)        // report the whole buf as "parsed" (or n = i?)
		retOkErr = ErrHdrOk // or ErrHdrMoreBytes ?
		goto endOfHdr
	}
	return i, ErrHdrMoreBytes
moreValues:
	// here i will point to the first char of the new value
	retOkErr = ErrHdrMoreValues
	n = i
	crl = 0
	switch param.state {
	case paramFNxt:
		// init state but for next param
		param.state = paramInitNxtVal
	default:
		param.state = paramERR
		return n + crl, ErrHdrBug
	}
	return n + crl, retOkErr
endOfHdr: // end of header found
	// here i will point to first WS char (including CR & LF)
	//      n will point to the line end (CR or LF)
	//      crl will contain the line end length (1 or 2) so that
	//      n+crl is the first char in the new header
	switch param.state {
	case paramInit, paramInitNxtVal:
		// end of header without finding a param = > empty
		return n + crl, ErrHdrEOH
	case paramFNxt, paramName, paramFEq, paramFVal, paramVal, paramFSep:
		param.state = paramFIN
	default:
		param.state = paramERR
		return n + crl, ErrHdrBug
	}
	return n + crl, ErrHdrEOH
}
