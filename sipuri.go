package sipsp

import (
	//	"errors"
	"bytes"
	"fmt"

	"andrei/sipsp/bytescase"
)

// TODO: unit test

func DBG(f string, a ...interface{}) {
	fmt.Printf("sipsp: "+f, a...)
}

// SIPStr is the "string" type used by all the sip parsing functions.
type SIPStr []byte

// ErrorURI is the type for the errors returned by Parse
type ErrorURI uint32

// possible error value
const (
	NoURIErr ErrorURI = iota
	ErrURIBadChar
	ErrURIScheme
	ErrURIHost
	ErrURIPort
	ErrURIHeaders
	ErrURITooShort
	ErrURIBad
	ErrURIBug
)

var errURIStr = [...]string{
	NoURIErr:       "no error",
	ErrURIBadChar:  "bad character in URI",
	ErrURIScheme:   "Invalid URI scheme",
	ErrURIHost:     "invalid URI host",
	ErrURIPort:     "invalid URI port",
	ErrURIHeaders:  "error parsing URI headers",
	ErrURITooShort: "uri too short",
	ErrURIBad:      "bad URI",
	ErrURIBug:      "internal BUG while parsing the URI",
}

func (e ErrorURI) Error() string {
	return errURIStr[e]
}

// URIScheme is the type for possible uri schemes (sips, sip, tel...).
type URIScheme int8

// enum
const (
	INVALIDuri URIScheme = iota
	SIPuri
	SIPSuri
	TELuri
)

func (s URIScheme) String() string {
	URISchemeStr := [...]string{
		"invalid",
		"sip",
		"sips",
		"tel",
	}
	if s < 0 || int(s) >= len(URISchemeStr) {
		return "error"
	}
	return URISchemeStr[s]
}

// PsipURI is a structure containing sip uri elements (scheme, user, host...).
type PsipURI struct {
	URIType URIScheme
	Scheme  PField
	User    PField
	Pass    PField
	Host    PField
	Port    PField
	Params  PField
	Headers PField
	PortNo  uint16
}

func (u *PsipURI) Reset() {
	*u = PsipURI{}
}

// Flat returns a byte slices containing the uri in "string" form.
func (u *PsipURI) Flat(buf []byte) []byte {

	var r PField

	if u.Headers.Len > 0 {
		r.Set(int(u.Scheme.Offs), int(u.Headers.Offs+u.Headers.Len))
	} else if u.Pass.Len > 0 {
		r.Set(int(u.Scheme.Offs), int(u.Params.Offs+u.Params.Len))
	} else if u.Port.Len > 0 {
		r.Set(int(u.Scheme.Offs), int(u.Port.Offs+u.Port.Len))
	} else if u.Host.Len > 0 {
		r.Set(int(u.Scheme.Offs), int(u.Host.Offs+u.Host.Len))
	} else if u.User.Len > 0 {
		r.Set(int(u.Scheme.Offs), int(u.User.Offs+u.User.Len))
	}
	return r.Get(buf)
}

// Short returns a "shortened" uri form, good for comparisons.
// no parameters or headers are included
func (u *PsipURI) Short() PField {
	var r PField

	if u.Port.Len > 0 {
		r.Set(int(u.Scheme.Offs), int(u.Port.Offs+u.Port.Len))
	} else if u.Host.Len > 0 {
		r.Set(int(u.Scheme.Offs), int(u.Host.Offs+u.Host.Len))
	} else if u.User.Len > 0 {
		r.Set(int(u.Scheme.Offs), int(u.User.Offs+u.User.Len))
	}
	return r
}

// Truncate "shortens" a parsed uri, by removing the parameters and headers
func (u *PsipURI) Truncate() {
	u.Params.Reset()
	u.Headers.Reset()
}

func (u *PsipURI) AdjustOffs(newpos PField) bool {
	offs := newpos.Offs // new start
	end := offs + newpos.Len
	if (u.Scheme.Len + u.User.Len + u.Pass.Len + u.Host.Len + u.Port.Len +
		u.Params.Len + u.Headers.Len) > newpos.Len {
		DBG("AdjustOffs: %d > %d\n", u.Scheme.Len+u.User.Len+u.Pass.Len+u.Host.Len+u.Port.Len+u.Params.Len+u.Headers.Len, newpos.Len)
		return false
	}
	start := u.Scheme.Offs
	last := offs
	u.Scheme.Offs = offs
	if u.User.Offs != 0 {
		u.User.Offs = u.User.Offs - start + offs
		last = u.User.Offs + u.User.Len
	}
	if u.Pass.Offs != 0 {
		u.Pass.Offs = u.Pass.Offs - start + offs
		last = u.Pass.Offs + u.Pass.Len
	}
	if u.Host.Offs != 0 {
		u.Host.Offs = u.Host.Offs - start + offs
		last = u.Host.Offs + u.Host.Len
	}
	if u.Port.Offs != 0 {
		u.Port.Offs = u.Port.Offs - start + offs
		last = u.Port.Offs + u.Port.Len
	}
	if u.Headers.Offs != 0 {
		u.Headers.Offs = u.Headers.Offs - start + offs
		last = u.Headers.Offs + u.Headers.Len
	}
	if last > end {
		panic("PsipURI.AdjustOffs: offset past end")
	}
	return true
}

// CmpShort compares 2 "shortened" uris (up to port, not including parameters
// or headers).
// Note that this is not a proper URI comparison (acccording to RFC3261 the
// common parameters must match, user, ttl, method and maddr must either appear
// in both URIs or in none and any present header must appear in both URIs to
// match).
func URICmpShort(u1 *PsipURI, buf1 []byte, u2 *PsipURI, buf2 []byte) bool {
	return u1.URIType == u2.URIType && u1.PortNo == u2.PortNo &&
		bytes.Equal(u1.User.Get(buf1), u2.User.Get(buf2)) &&
		bytes.Equal(u1.Pass.Get(buf1), u2.Pass.Get(buf2)) &&
		bytescase.CmpEq(u1.Host.Get(buf1), u2.Host.Get(buf2))
}

// Parse parses a sip uri into a PSIPUri structure.
// Note: PsipURI members will point into the original SipStr
// Returns err = 0 on success, or error and the parsed-so-far offset.
// TODO: tel uri emebeded in sip (user=phone param)
// TODO: specific tel uri parser
// TODO: parse important parameters like transport and user automatically
func ParseURI(uri SIPStr, puri *PsipURI) (ErrorURI, int) {
	const (
		SchSIP  uint32 = 0x3a706973 // "sip:"
		SchSIPS        = 0x73706973 // "sips"
		SchTEL         = 0x3a6c6574 //  "tel:"
	)

	// big internal uri parser state enum
	const (
		uInit uint32 = iota
		uInitSIP
		uInitSIPS
		uInitTEL
		uSIP
		uSIPS
		uTEL
		uUser
		uPass0
		uPass1
		uHost0
		uHost1
		uHost61
		uHost6E
		uPort
		uParam0 // possible param start
		uParam1 // parsing param
		uHeaders
	)

	// sanity checks, no sip uri can be less then 5 (shortest uri : "sip:X")
	if len(uri) < 5 {
		return ErrURITooShort, len(uri)
	}
	var offs int
	var sch uint32
	state := uInit
	// set sch to the case insensitive version of the 1st 4 chars
	sch = ((uint32(uri[3]) << 24) | (uint32(uri[2]) << 16) |
		(uint32(uri[1]) << 8) | (uint32(uri[0]))) |
		0x20202020
	var schLen int

	switch sch {
	case SchSIP:
		puri.URIType = SIPuri
		state = uInitSIP
		schLen = 3
	case SchTEL:
		puri.URIType = TELuri
		state = uInitTEL
		schLen = 3
	case SchSIPS:
		if uri[4] == ':' {
			puri.URIType = SIPSuri
			state = uInitSIPS
			schLen = 4
		} else {
			puri.URIType = INVALIDuri
			return ErrURIScheme, 4
		}
	default:
		puri.URIType = INVALIDuri
		return ErrURIScheme, 4
	}
	puri.Scheme.Set(offs, offs+schLen+1) // include ":"
	offs += schLen + 1                   // skip over ':' and point to next char
	var s int                            // current element starting offset
	var foundUser bool
	var passOffs int // possible password candidate offset
	var portNo int
	var errHeaders bool // possible header error
	i := offs
	var c byte
	for ; i < len(uri); i++ {
		c = uri[i]
		//DBG("ParseURI: parsing %s_%c state %d i %d s %d\n", uri[:i], c, state, i, s)
		switch state {
		case uInitSIP, uInitSIPS, uInitTEL:
			switch c {
			case '[': // ipv6 addr: [ipv6]
				state = uHost61
				s = i
			case ':', ']': // invalid char at uri start
				return ErrURIBadChar, i
			default:
				state = uUser
				s = i
			}
		case uUser:
			switch c {
			case '@':
				puri.User.Set(s, i)
				state = uHost0
				foundUser = true
				s = i + 1 // skip over '@' for the start of the host part
			case ':':
				// we either found the password (e.g. sip:foo:pass@bar.org) or
				// this URI has no user part and we found the port
				// (e.g. bar.org:123)
				puri.User.Set(s, i)
				state = uPass0
				s = i + 1 //skip over ':'
			case ';':
				// no user, we found a possible param (e.g. sip:bar.org;p)
				// but it could also be a user containing  ';', e.g.:
				// sip:user;x@foo.bar
				puri.Host.Set(s, i)
				state = uParam0
				s = i + 1 // skip over ';'
			case '?':
				// possible headers start (e.g. sip:bar.org?headers)
				// but it could also be a user containing '?', e.g.:
				// sip:user?x@foo.bar
				puri.Host.Set(s, i)
				state = uHeaders
				s = i + 1
			case '[', ']':
				return ErrURIBadChar, i
			}
		case uPass0: // this might be the password or the port part of the uri
			switch c {
			case '@':
				puri.Pass.Set(s, i)
				portNo = 0 // reset port no
				state = uHost0
				foundUser = true
				s = i + 1 // skip over '@'
			case ';', '?':
				//  param or header => this means this was in fact the port
				//  e.g.: sip:foo:5060;param
				puri.Port.Set(s, i)
				if portNo > 65535 {
					return ErrURIPort, i
				}
				puri.PortNo = uint16(portNo)
				// the user part contains the host => fix it
				puri.Host = puri.User
				puri.User.Reset()
				foundUser = true // user part is empty, but we "found" it
				s = i + 1
				if c == ';' {
					state = uParam0
				} else {
					state = uHeaders
				}
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				// in case this might be the port no, compute it
				portNo = portNo*10 + int(c-'0')
			case '[', ']', ':':
				return ErrURIBadChar, i
			default:
				// non-number non-terminator found => this is not the port
				// it's the password
				portNo = 0
				state = uPass1
			}
		case uPass1: // this is the password for sure (non num. char found)
			switch c {
			case '@':
				puri.Pass.Set(s, i)
				state = uHost0
				foundUser = true
				s = i + 1 // skip over '@'
			case ';', '?', '[', ']', ':':
				return ErrURIBadChar, i
			}
		case uHost0:
			switch c {
			case '[':
				state = uHost61
			case ':', ';', '?', '&', '@':
				// empty host part or invalid chars in host name
				return ErrURIHost, i
			default:
				state = uHost1
			}
		case uHost1:
			switch c {
			case ':':
				puri.Host.Set(s, i)
				state = uPort
				s = i + 1
			case ';':
				puri.Host.Set(s, i)
				state = uParam0
				s = i + 1
			case '?':
				puri.Host.Set(s, i)
				state = uHeaders
				s = i + 1
			case '&', '@':
				return ErrURIBadChar, i
			}
		case uHost61:
			switch c {
			case ']':
				state = uHost6E
			case '[', '@', ';', '?', '&':
				return ErrURIHost, i
			}
		case uHost6E:
			switch c {
			case ':':
				puri.Host.Set(s, i)
				state = uPort
				s = i + 1
			case ';':
				puri.Host.Set(s, i)
				state = uParam0
				s = i + 1
			case '?':
				puri.Host.Set(s, i)
				state = uHeaders
				s = i + 1
			default: // nothing allowed after [ipv6addr]
				return ErrURIHost, i
			}
		case uPort:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				portNo = portNo*10 + int(c-'0')
			case ';':
				puri.Port.Set(s, i)
				if portNo > 65535 {
					return ErrURIPort, i
				}
				puri.PortNo = uint16(portNo)
				state = uParam0
				s = i + 1
			case '?':
				puri.Port.Set(s, i)
				if portNo > 65535 {
					return ErrURIPort, i
				}
				puri.PortNo = uint16(portNo)
				state = uHeaders
				s = i + 1
			default:
				return ErrURIPort, i
			}
		case uParam0, uParam1: // start of params or inside of params
			switch c {
			case '@':
				// this might be in fact the user (a user part containing ';')
				// e.g. sip:user;@foo.bar , or
				// for uParams1: sip:user;x=1@foo.bar
				if foundUser == false {
					if passOffs != 0 {
						// if also found a possible password candidate
						puri.User.Set(int(puri.Host.Offs), passOffs)
						puri.Pass.Set(passOffs+1, i)
					} else {
						puri.User.Set(int(puri.Host.Offs), i)
						puri.Pass.Reset() // make sure the password is empty
					}
					// reset everything else, we have to restart at host
					foundUser = true
					errHeaders = false
					state = uHost0
					s = i + 1
					puri.Host.Reset()
					puri.Port.Reset()
					puri.PortNo = 0
					puri.Params.Reset()
					puri.Headers.Reset()
				} else {
					return ErrURIBadChar, i
				}
			case ':':
				if foundUser == false {
					// if the user was not found yet, this might be the pass'
					// (what's before is a user containing ';', e.g.:
					// sip:u;:pass@foo.bar ) or it might be a param starting
					// with ':' (e.g.: sip: foo.bar;:p )
					if passOffs != 0 {
						foundUser = true // no user
						passOffs = 0     // cannot be password
					} else { // this is a password candidate
						passOffs = i
					}
				}
				state = uParam1
			case ';':
				if passOffs != 0 {
					// ';' not allowed in pass => this can't be the password
					passOffs = 0
					foundUser = true // empty user, don't have to look for it
				}
				state = uParam0 // new param. start
			case '?':
				// possible start of headers
				puri.Params.Set(s, i)
				state = uHeaders
				s = i + 1
				if passOffs != 0 {
					passOffs = 0
					foundUser = true // no user (no '?' allowed in password)
				}
			default:
				state = uParam1
			}
		case uHeaders:
			switch c {
			case '@':
				// this might be in fact the user (a user part containing '?')
				// e.g. sip:user?@foo.bar , or sip:user?x@foo.bar
				if foundUser == false {
					if passOffs != 0 {
						// if also found a possible password candidate
						// e.g.: sip:user?x:pass@foo.bar
						puri.User.Set(int(puri.Host.Offs), passOffs)
						puri.Pass.Set(passOffs+1, i)
					} else {
						puri.User.Set(int(puri.Host.Offs), i)
						puri.Pass.Reset() // make sure the password is empty
					}
					// reset everything else, we have to restart at host
					foundUser = true
					errHeaders = false
					state = uHost0
					s = i + 1
					puri.Host.Reset()
					puri.Port.Reset()
					puri.PortNo = 0
					puri.Params.Reset()
					puri.Headers.Reset()
				} else {
					return ErrURIBadChar, i
				}
			case ';':
				// this might be still the user, e.g.: sip:user?x;y@foo.bar
				if foundUser || passOffs != 0 {
					// if user already found or ':' found => error
					// (';' not valid inside a header)
					return ErrURIBadChar, i
				}
				errHeaders = true // if this is not the user => error
			case ':':
				// might be a password if the user was not found, else it's
				// a normal header char
				if foundUser == false {
					if passOffs != 0 {
						foundUser = true // no user
						// e.g.: foo?h:b:c=x
						passOffs = 0
					} else {
						// e.g.: sip:user?x:pass@foo.bar
						passOffs = i
					}
				}
			case '?':
				if passOffs != 0 {
					foundUser = true // no user, no '?' allowed in password
					// e.g.: sip:foo?x:p?z
					passOffs = 0
				}
			}
		} // end of switch(state)
	} // end of input (for i)
	switch state {
	case uInit, uInitTEL, uInitSIP, uInitSIPS:
		return ErrURITooShort, i
	case uUser:
		// no host or '@' found => it means this is in fact the host
		// (e.g.  sip:foo)
		if foundUser { // if '@' found
			return ErrURIBad, i
		}
		puri.Host.Set(s, i)
		state = uHost0
	case uPass0, uPass1:
		// e.g.: sip:foo:123  -> this is really the password
		if foundUser || state == uPass1 {
			return ErrURIPort, i
		}
		puri.Port.Set(s, i)
		if portNo > 65535 {
			return ErrURIPort, i
		}
		puri.PortNo = uint16(portNo)
		puri.Host = puri.User
		puri.User.Reset()
	case uHost1, uHost6E:
		puri.Host.Set(s, i)
	case uHost0, uHost61:
		// error empty host or unterminated ipv6 (e.g. [ipv6...])
		return ErrURIHost, i
	case uPort:
		puri.Port.Set(s, i)
		if portNo > 65535 {
			return ErrURIPort, i
		}
		puri.PortNo = uint16(portNo)
	case uParam0, uParam1:
		puri.Params.Set(s, i)
	case uHeaders:
		puri.Headers.Set(s, i)
		if errHeaders {
			return ErrURIHeaders, i
		}
	default:
		return ErrURIBug, i
	}
	// uri type specific fixes

	if puri.URIType == TELuri {
		// for tel: uris we keep the number in the user part and the
		//          host part will be empty
		puri.User = puri.Host
		puri.Host.Reset()
	}

	return 0, i
}
