// Copyright 2022 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

package sipsp

import (
	"bytes"
	"testing"
)

func TestParseURI(t *testing.T) {
	type expR struct {
		schN   URIScheme
		sch    string
		user   string
		pass   string
		host   string
		port   string
		portNo uint16
		params string
		hdrs   string
		err    ErrorURI
		o      int // offs after parsing
	}
	type testCase struct {
		u    string // uri
		eRes expR   // expected result
	}

	testCases := [...]testCase{
		{
			u: "sip:a@foo.bar:5060;p1=1;p2=2?h1=1&h2=2",
			eRes: expR{
				schN:   SIPuri,
				sch:    "sip:",
				user:   "a",
				host:   "foo.bar",
				port:   "5060",
				portNo: 5060,
				params: "p1=1;p2=2",
				hdrs:   "h1=1&h2=2",
				err:    0,
				o:      38,
			},
		},
		{
			u: "sips:foo.bar;p1=1;p2=2",
			eRes: expR{
				schN:   SIPSuri,
				sch:    "sips:",
				user:   "",
				host:   "foo.bar",
				port:   "",
				portNo: 0,
				params: "p1=1;p2=2",
				hdrs:   "",
				err:    0,
				o:      22,
			},
		},
		{
			u: "sip:test:pass1@foo.bar;p1=1&b;p2=2:2",
			eRes: expR{
				schN:   SIPuri,
				sch:    "sip:",
				user:   "test",
				pass:   "pass1",
				host:   "foo.bar",
				port:   "",
				portNo: 0,
				params: "p1=1&b;p2=2:2",
				hdrs:   "",
				err:    0,
				o:      36,
			},
		},
		{
			u: "tel:+358-555-1234567;postd=pp22",
			eRes: expR{
				schN:   TELuri,
				sch:    "tel:",
				user:   "+358-555-1234567",
				host:   "",
				port:   "",
				portNo: 0,
				params: "postd=pp22",
				hdrs:   "",
				err:    0,
				o:      31,
			},
		},
		{
			u: "sip:+358-555-1234567;postd=pp22@foo.com;user=phone",
			eRes: expR{
				schN:   SIPuri,
				sch:    "sip:",
				user:   "+358-555-1234567;postd=pp22",
				host:   "foo.com",
				port:   "",
				portNo: 0,
				params: "user=phone",
				hdrs:   "",
				err:    0,
				o:      50,
			},
		},
		{
			u: "sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com",
			eRes: expR{
				schN:   SIPuri,
				sch:    "sip:",
				user:   "",
				host:   "biloxi.com",
				port:   "",
				portNo: 0,
				params: "transport=tcp;method=REGISTER",
				hdrs:   "to=sip:bob%40biloxi.com",
				err:    0,
				o:      68,
			},
		},
		{
			u: "sip:carol@chicago.com?Subject=next%20meeting",
			eRes: expR{
				schN:   SIPuri,
				sch:    "sip:",
				user:   "carol",
				host:   "chicago.com",
				port:   "",
				portNo: 0,
				params: "",
				hdrs:   "Subject=next%20meeting",
				err:    0,
				o:      44,
			},
		},
	}

	for i, tc := range testCases {
		var pu PsipURI

		buf := []byte(tc.u)
		err, o := ParseURI(buf, &pu)

		if err != tc.eRes.err {
			t.Errorf("ParseURI(%q, ...) = %d (%s) o %d "+
				" err %d (%s) != expected %d (%s) (test case %d)",
				tc.u, err, err, o,
				err, err, tc.eRes.err, tc.eRes.err, i+1)
		}

		if pu.URIType != tc.eRes.schN && tc.eRes.schN != 0 {
			t.Errorf("ParseURI(%q, ...) = %d (%s) o %d "+
				" uri type %d  != expected type %d (test case %d)",
				tc.u, err, err, o,
				pu.URIType, tc.eRes.schN, i+1)
		}
		if !bytes.Equal(pu.Scheme.Get(buf), []byte(tc.eRes.sch)) {
			t.Errorf("ParseURI(%q, ...) = %d (%s) o %d "+
				" uri scheme %q  != expected scheme %q (test case %d)",
				tc.u, err, err, o,
				pu.Scheme.Get(buf), tc.eRes.sch, i+1)
		}
		if !bytes.Equal(pu.User.Get(buf), []byte(tc.eRes.user)) {
			t.Errorf("ParseURI(%q, ...) = %d (%s) o %d "+
				" uri user %q  != expected user %q (test case %d)",
				tc.u, err, err, o,
				pu.User.Get(buf), tc.eRes.user, i+1)
		}
		if !bytes.Equal(pu.Pass.Get(buf), []byte(tc.eRes.pass)) {
			t.Errorf("ParseURI(%q, ...) = %d (%s) o %d "+
				" uri pass %q  != expected pass %q (test case %d)",
				tc.u, err, err, o,
				pu.Pass.Get(buf), tc.eRes.pass, i+1)
		}
		if !bytes.Equal(pu.Host.Get(buf), []byte(tc.eRes.host)) {
			t.Errorf("ParseURI(%q, ...) = %d (%s) o %d "+
				" uri host %q  != expected host %q (test case %d)",
				tc.u, err, err, o,
				pu.Host.Get(buf), tc.eRes.host, i+1)
		}
		if pu.PortNo != tc.eRes.portNo {
			t.Errorf("ParseURI(%q, ...) = %d (%s) o %d "+
				" uri num. port %d  != expected num. port %d (test case %d)",
				tc.u, err, err, o,
				pu.PortNo, tc.eRes.portNo, i+1)
		}
		if !bytes.Equal(pu.Port.Get(buf), []byte(tc.eRes.port)) {
			t.Errorf("ParseURI(%q, ...) = %d (%s) o %d "+
				" uri port %q  != expected port %q (test case %d)",
				tc.u, err, err, o,
				pu.Port.Get(buf), tc.eRes.port, i+1)
		}
		if !bytes.Equal(pu.Params.Get(buf), []byte(tc.eRes.params)) {
			t.Errorf("ParseURI(%q, ...) = %d (%s) o %d "+
				" uri params %q  != expected params %q (test case %d)",
				tc.u, err, err, o,
				pu.Params.Get(buf), tc.eRes.params, i+1)
		}
		if !bytes.Equal(pu.Headers.Get(buf), []byte(tc.eRes.hdrs)) {
			t.Errorf("ParseURI(%q, ...) = %d (%s) o %d "+
				" uri hdrs %q  != expected hdrs %q (test case %d)",
				tc.u, err, err, o,
				pu.Headers.Get(buf), tc.eRes.hdrs, i+1)
		}

		if o != tc.eRes.o && tc.eRes.o != 0 {
			t.Errorf("ParseURI(%q, ...) = %d (%s) o %d "+
				" offs %d  != expected  offs %d (test case %d)",
				tc.u, err, err, o,
				o, tc.eRes.o, i+1)
		}
	}
}

func TestUriCmp(t *testing.T) {
	type expR struct {
		res bool
		err ErrorURI
		uN  int // uri for which parsing failed
	}
	type testCase struct {
		u1   string      // uri1
		u2   string      // uri2
		f    URICmpFlags // uri cmp flags
		eRes expR        // expected result
	}

	testCases := [...]testCase{
		{
			u1:   "sip:a@foo.bar",
			u2:   "sip:a@FOO.BaR",
			f:    0,
			eRes: expR{true, 0, 0},
		},
		{
			u1:   "sip:%61lice@atlanta.com;transport=TCP",
			u2:   "sip:alice@AtLanTa.CoM;Transport=tcp",
			f:    0,
			eRes: expR{false, 0, 0}, // no unsecape support so far
		},
		{
			u1:   "sip:%61lice@atlanta.com;transport=TCP",
			u2:   "sip:alice@AtLanTa.CoM;Transport=tcp",
			f:    URICmpSkipUser,
			eRes: expR{true, 0, 0}, // user ignored
		},
		{
			u1:   "",
			u2:   "",
			f:    0,
			eRes: expR{false, ErrURITooShort, 0},
		},
		{
			u1:   "sip:carol@chicago.com",
			u2:   "sip:carol@chicago.com;newparam=5",
			f:    0,
			eRes: expR{true, 0, 0},
		},
		{
			u1:   "sip:carol@chicago.com;newparam=5",
			u2:   "sip:carol@chicago.com;security=on",
			f:    0,
			eRes: expR{true, 0, 0},
		},
		{
			u1:   "sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com",
			u2:   "sip:biloxi.com;method=REGISTER;transport=tcp?to=sip:bob%40biloxi.com",
			f:    0,
			eRes: expR{true, 0, 0},
		},
		{
			u1:   "sip:alice@atlanta.com?subject=project%20x&priority=urgent",
			u2:   "sip:alice@atlanta.com?priority=urgent&subject=project%20x",
			f:    0,
			eRes: expR{true, 0, 0},
		},
		{
			u1:   "SIP:ALICE@AtLanTa.CoM;Transport=udp",
			u2:   "sip:alice@AtLanTa.CoM;Transport=UDP",
			f:    0,
			eRes: expR{false, 0, 0}, // diff usernames
		},
		{
			u1:   "sip:bob@biloxi.com",
			u2:   "sip:bob@biloxi.com:5060",
			f:    0,
			eRes: expR{false, 0, 0}, // diff ports
		},
		{
			u1:   "sip:bob@biloxi.com",
			u2:   "sip:bob@biloxi.com:5060",
			f:    URICmpSkipPort,
			eRes: expR{true, 0, 0}, // ports ignored
		},
		{
			u1:   "sip:bob@biloxi.com;transport=udp",
			u2:   "sip:bob@biloxi.com;transport=tcp",
			f:    0,
			eRes: expR{false, 0, 0}, // diff transport
		},
		{
			u1:   "sip:bob@biloxi.com;transport=udp",
			u2:   "sip:bob@biloxi.com;transport=tcp",
			f:    URICmpSkipParams,
			eRes: expR{true, 0, 0}, // diff transport, but ignored params
		},
		{
			u1:   "sip:bob@biloxi.com;transport=udp",
			u2:   "sip:bob@biloxi.com:6000;transport=tcp",
			f:    0,
			eRes: expR{false, 0, 0}, // diff port & transport
		},
		{
			u1:   "sip:bob@biloxi.com;transport=udp",
			u2:   "sip:bob@biloxi.com:6000;transport=tcp",
			f:    URICmpSkipPort,
			eRes: expR{false, 0, 0}, // diff  transport
		},
		{
			u1:   "sip:bob@biloxi.com;transport=udp",
			u2:   "sip:bob@biloxi.com:6000;transport=tcp",
			f:    URICmpSkipPort | URICmpSkipParams,
			eRes: expR{true, 0, 0}, // diff  port & transport, but ignored
		},
		{
			u1:   "sip:carol@chicago.com",
			u2:   "sip:carol@chicago.com?Subject=next%20meeting",
			f:    0,
			eRes: expR{false, 0, 0}, // diff hdrs
		},
		{
			u1:   "sip:carol@chicago.com",
			u2:   "sip:carol@chicago.com?Subject=next%20meeting",
			f:    URICmpSkipHeaders,
			eRes: expR{true, 0, 0}, // diff hdrs, but ignored
		},
		{
			u1:   "tel:+358-555-1234567;postd=pp22",
			u2:   "tel:+358-555-1234567;POSTD=PP22",
			f:    0,
			eRes: expR{true, 0, 0},
		},
		{
			u1:   "tel:+358-555-1234567;postd=pp22;isub=1411",
			u2:   "tel:+358-555-1234567;isub=1411;postd=pp22",
			f:    0,
			eRes: expR{true, 0, 0},
		},
	}
	for i, tc := range testCases {
		res, err, n := URIRawCmp([]byte(tc.u1), []byte(tc.u2), tc.f)

		if res != tc.eRes.res {
			t.Errorf("URIRawCmp(%q, %q, 0x%x) = %v,  %d (%s) u%d "+
				" res %v != expected %v (test case %d)",
				tc.u1, tc.u2, tc.f, res, err, err, n,
				res, tc.eRes.res, i+1)
		}
		if err != tc.eRes.err {
			t.Errorf("URIRawCmp(%q, %q, 0x%x) = %v,  %d (%s) u%d "+
				" err %d (%s) != expected %d (%s) (test case %d)",
				tc.u1, tc.u2, tc.f, res, err, err, n,
				err, err, tc.eRes.err, tc.eRes.err, i+1)
		}
		if n != tc.eRes.uN {
			t.Errorf("URIRawCmp(%q, %q, 0x%x) = %v,  %d (%s) u%d "+
				" failed uri number %d != expected %d (test case %d)",
				tc.u1, tc.u2, tc.f, res, err, err, n,
				n, tc.eRes.uN, i+1)
		}
	}
}
