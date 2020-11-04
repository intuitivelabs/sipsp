package sipsp

import (
	"bytes"
	// fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	//	"log"

	"github.com/intuitivelabs/bytescase"
)

func TestMain(m *testing.M) {
	res := m.Run()
	os.Exit(res)
}

func TestParseFromVal1(t *testing.T) {
	type testCase struct {
		t      []byte    // test "string"
		offs   int       // offset in t
		ePFrom PFromBody // expected parsed from body
		eOffs  int       // expected offset
		eErr   ErrorHdr  // expected error
	}
	tests := [...]testCase{
		{[]byte("Foo Bar <sip:f@bar.com>;x=y\r\nX"), 0,
			PFromBody{Name: PField{0, 8}, URI: PField{9, 13},
				Params: PField{24, 3}, Tag: PField{0, 0}},
			29 /* \r offset */, ErrHdrOk},
	}
	var pf PFromBody
	for _, tc := range tests {
		o, err := ParseFromVal(tc.t, tc.offs, &pf)
		if err != tc.eErr {
			t.Errorf("ParseFromVal(%q, %d, ..)=[%d, %d(%q)] expected error %d (%q)",
				tc.t, tc.offs, o, err, err, tc.eErr, tc.eErr)
		}
		if o != tc.eOffs {
			t.Errorf("ParseFromVal(%q, %d, ..)=[%d, %d(%q)] expected offs %d",
				tc.t, tc.offs, o, err, err, tc.eOffs)
		}

		if !pf.Parsed() {
			t.Errorf("ParseFromVal(%q, %d, ..)=[%d, %d(%q)]"+
				" not fully parsed: %d",
				tc.t, tc.offs, o, err, err, pf.state)
		}
		pf.Reset()
	}
}

func TestParseFromVal2(t *testing.T) {
	names := [...]string{
		"",
		"Display Name",
		"ShortName",
		" WS Name Front",
		"WS Name End 	",
		"CRLF\r\n Name",
		"\r\n CRLF Name Front",
		"CRLF Name End\r\n ",
		"  \r\n 	CRLF\r\n Name \r\n ",
		"sip:urilike.name",
		"sip:host:5060",
		"sip:x@f.b:1234",
		"\"Anonymous\"",
		"\"00:42:60:e1:5c:a8\"",
		"\"J Rosenberg \\\"\"",
	}

	uris := [...]string{
		"sip:u1@test",
		"sip:u1@test.org",
		"sip:test.org",
		"sip:test.org;param",
		"sip:test.org;param=v",
		"sip:test.org;param=v;param2",
		"sip:test.org;param=v;param2=v2",
		"sip:test.org;p1;p2=v2",
		"sip:test.org;p;t=xx;p2=v",
		"sip:anonymous@anonymous.invalid",
		"sip:100@1.1.1.1",
	}
	params := [...]string{
		"",
		"p",
		"p1=v1",
		"p1=v1;p",
		"p=v;p1=v1",
		" p =  v ; p1 = v1",
		" \r\n p =  v \r\n ; p1\r\n =\r\n v1",
		"p=\"test\r\n new line\"",
	}
	tagsv := [...]string{
		"", "xxxx", "AbcdE",
		"hu3odsomep",
		"6434346636663962313363340131303638393837373538",
	}

	//var pf PFromBody
	for _, n := range names {
		for _, u := range uris {
			for _, p := range params {
				for _, tagv := range tagsv {
					//str := n + "<" + u + ">" + ";" + p + ";" + "tag=" +tagv + "\r\n\r\n"
					/*
						var str, params string
						str, params = genFromBody(n, u, p, tagv, true)
						str += "\r\n\r\n"
						b := []byte(str)
						pf.Reset()
						o, err := ParseFromVal(b, 0, &pf)
						if err != 0 {
							t.Errorf("ParseFromVal(%q, %d, ..)=[%d, %d(%q)] no error expected, state %d soffs %d",
								b, 0, o, err, err, pf.state, pf.soffs)
						}
					*/
					testParseFromComp(t, n, u, p, tagv)
				}
			}
		}
	}
}

type fromExpRes struct {
	err    ErrorHdr
	offs   int
	name   []byte
	uri    []byte
	params []byte
	tag    []byte
	v      []byte // whole body, trimmed
}

func TestParseFromVal3(t *testing.T) {
	type expRes struct {
		err  ErrorHdr
		offs int
		name string
		uri  string
		p    string // params
		tagv string
	}

	type testCase struct {
		fb string // from body w/o term. CRLF
		expRes
	}
	var exp fromExpRes
	var b []byte

	tests := [...]testCase{
		{fb: "Foo Bar <sip:f@bar.com>;x=y;tag=Abcd",
			expRes: expRes{err: 0, name: "Foo Bar", uri: "sip:f@bar.com",
				p: "x=y;tag=Abcd", tagv: "Abcd"}},
		{fb: " \"Anonymous\" <sip:anonymous@anonymous.invalid>;tag=hu3odsomep",
			expRes: expRes{err: 0, name: "\"Anonymous\"",
				uri: "sip:anonymous@anonymous.invalid",
				p:   "tag=hu3odsomep", tagv: "hu3odsomep"}},
		{fb: "  \"J Rosenberg \\\\\\\"\"       <sip:jdrosen@example.com> ; tag = 98asjd8",
			expRes: expRes{err: 0, name: "\"J Rosenberg \\\\\\\"\"",
				uri: "sip:jdrosen@example.com",
				p:   "tag = 98asjd8", tagv: "98asjd8"}},
		{fb: "<sip:I%20have%20spaces@example.net>;tag=938",
			expRes: expRes{err: 0, name: "",
				uri: "sip:I%20have%20spaces@example.net",
				p:   "tag=938", tagv: "938"}},
		{fb: " sip:null-%00-null@example.com;tag=839923423",
			expRes: expRes{err: 0, name: "",
				uri: "sip:null-%00-null@example.com",
				p:   "tag=839923423", tagv: "839923423"}},
		{fb: "sip:'or''='@52.67.103.243;tag=123",
			expRes: expRes{err: 0, name: "",
				uri: "sip:'or''='@52.67.103.243",
				p:   "tag=123", tagv: "123"}},
		{fb: "sip:http%3a//foo%3aLwq5Z39aBar%40192.168.128.2%3a5000/dev/null/zero/ABA/end@example.ex",
			expRes: expRes{err: 0, name: "",
				uri: "sip:http%3a//foo%3aLwq5Z39aBar%40192.168.128.2%3a5000/dev/null/zero/ABA/end@example.ex",
				p:   "", tagv: ""}},
		{fb: "Anonymous <sip:anonymous@10.11.12.13;user=phone>;tag=9cel7cft-BA-81",
			expRes: expRes{err: 0, name: "Anonymous",
				uri: "sip:anonymous@10.11.12.13;user=phone",
				p:   "tag=9cel7cft-BA-81", tagv: "9cel7cft-BA-81"}},
		// invalid uri, but passes from test (doesn't check uri validity)
		{fb: "sip:sip:fo-test.tst;tag=AI31AFBED1B5EB6BCE",
			expRes: expRes{err: 0, offs: 0,
				name: "", uri: "sip:sip:fo-test.tst",
				p: "tag=AI31AFBED1B5EB6BCE", tagv: "AI31AFBED1B5EB6BCE"}},
		// invalid addr-spec (multiple '<')
		{fb: "<sip: <sip:test>badfrom.t>;tag=C471EBDB-1BE3",
			expRes: expRes{err: ErrHdrBadChar, offs: 5,
				name: "", uri: "", p: "", tagv: ""}},
		{fb: "<sip:*@192.168.197.34>;tag=932837435",
			expRes: expRes{err: 0, offs: 0,
				name: "", uri: "sip:*@192.168.197.34",
				p: "tag=932837435", tagv: "932837435"}},
		{fb: "<sip:4876@uc-support.foo.com>;X-sipX-referror=%7E%7Eid%7Emedia%40uc-support.foo.com;tag=2UKHKaBK3KmZN",
			expRes: expRes{err: 0, offs: 0,
				name: "", uri: "sip:4876@uc-support.foo.com",
				p:    "X-sipX-referror=%7E%7Eid%7Emedia%40uc-support.foo.com;tag=2UKHKaBK3KmZN",
				tagv: "2UKHKaBK3KmZN"}},
		{fb: "<sips:4211@foobar.com>;tag=2`FYiK",
			expRes: expRes{err: 0, offs: 0,
				name: "", uri: "sips:4211@foobar.com",
				p: "tag=2`FYiK", tagv: "2`FYiK"}},
		// missing \"
		{fb: "\"sipvicious <sip:100@1.1.1.1>;tag=6434346636663962313363340131303638393837373538",
			expRes: expRes{err: ErrHdrBad, offs: 0,
				name: "", uri: "", p: "", tagv: ""}},
		{fb: "\"sipvicious <sip:100@1.1.1.1>;tag=6434346636663962313363340131303638393837373538\r\n \"sipvicious <sip:100@1.1.1.1>;tag=6434346636663962313363340131303638393837373538",
			expRes: expRes{err: 0, offs: 0,
				name: "\"sipvicious <sip:100@1.1.1.1>;tag=6434346636663962313363340131303638393837373538\r\n \"sipvicious",
				uri:  "sip:100@1.1.1.1",
				p:    "tag=6434346636663962313363340131303638393837373538",
				tagv: "6434346636663962313363340131303638393837373538"}},
		// missing empty, missing ending \"
		{fb: " \"\\",
			expRes: expRes{err: ErrHdrBadChar, offs: 3,
				name: "", uri: "", p: "", tagv: ""}},
		{fb: "sip:u1@test.org \n \r\n ",
			expRes: expRes{err: 0, name: "", uri: "sip:u1@test.org",
				p: "", tagv: ""}},
	}

	for _, c := range tests {
		b = []byte(c.fb + "\r\n\r\n")
		if c.offs <= 0 { // offset not filled -> add it automatically
			exp.offs = len(b) - 2
		} else {
			exp.offs = c.offs
		}
		exp.err = c.err
		exp.name = []byte(c.name)
		exp.uri = []byte(c.uri)
		exp.params = []byte(c.p)
		exp.tag = []byte(c.tagv)
		exp.v = bytes.TrimSpace([]byte(c.fb))
		testParseFromExp(t, b, 0, exp)
	}

}

func testParseFromComp(t *testing.T, name, uri, params, tagv string) {

	var body string
	body, params = genFromBody(name, uri, params, tagv, true)
	var exp fromExpRes
	exp.name = []byte(name)
	if len(name) == 0 {
		// if name is empty, we might generate either <uri>;params
		// or uri;params
		if !strings.ContainsAny(body, "<") {
			// uri is not enclosed in <> => uri params are in fact
			// from params
			if i := strings.IndexByte(uri, ';'); i >= 0 {
				if len(params) != 0 {
					params = uri[i+1:] + ";" + params
				} else {
					params = uri[i+1:]
				}
				uri = uri[:i]
			}
		}
	}
	exp.uri = []byte(uri)
	exp.params = []byte(params)
	exp.tag = []byte(tagv)
	exp.v = bytes.TrimSpace([]byte(body))
	exp.offs = len(body) + 2
	exp.err = 0
	body += "\r\n\r\n"
	testParseFromExp(t, []byte(body), 0, exp)
}

func testParseFromExp(t *testing.T, buf []byte, offs int, e fromExpRes) {
	var pf PFromBody

	var sz int
	var o int
	var err ErrorHdr
	o = offs
	pieces := rand.Intn(10)
	var i int
	for ; i < pieces; i++ {
		sz = rand.Intn(len(buf) + 1 - o)
		end := sz + o
		if end < e.offs {
			o, err = ParseFromVal(buf[:end], o, &pf)
			if err != ErrHdrMoreBytes {
				t.Errorf("ParseFromVal partial %d (%q/%q, %d, .)=[%d, %d(%q)]"+
					" error %s (%q) expected, state %d soffs %d",
					i, buf[:end], buf, offs, o, err, err,
					ErrHdrMoreBytes, ErrHdrMoreBytes, pf.state, pf.soffs)
			}
			if pf.Parsed() {
				t.Errorf("ParseFromVal(%q, %d, ..)=[%d, %d(%q)]"+
					" unexpected full parsed state (%d) at this point ",
					buf, offs, o, err, err, pf.state)
			}
			// fmt.Printf("partial(%d) bytes %q -> continue at %d, state %d soffs %d\n", i, buf[:end], o, pf.state, pf.soffs)
		} else {
			break
		}
	}
	o, err = ParseFromVal(buf, o, &pf)
	/*
		if pieces > 0 {
			fmt.Printf("final(%d) bytes %q -> offset %d, err %d [%s], state %d soffs %d\n", i, buf, o, err, err, pf.state, pf.soffs)
		}
	*/
	if err != e.err {
		t.Errorf("ParseFromVal(%q, %d, ..)=[%d, %d(%q)]  error %s (%q) expected, state %d soffs %d",
			buf, offs, o, err, err, e.err, e.err, pf.state, pf.soffs)
	}
	if o != e.offs && e.offs != -1 {
		t.Errorf("ParseFromVal(%q, %d, ..)=[%d, %d(%q)]  offset %d expected, state %d soffs %d",
			buf, offs, o, err, err, e.offs, pf.state, pf.soffs)
	}
	if err != 0 {
		// no point in checking components if error
		return
	}
	if !checkTSliceEq(e.name, pf.Name.Get(buf)) {
		t.Errorf("ParseFromVal(%q, %d, ..)=[%d, %d(%q)]  name %q != %q (exp)",
			buf, offs, o, err, err, pf.Name.Get(buf), e.name)
	}
	// take whitespace into account
	if !bytescase.CmpEq(e.uri, pf.URI.Get(buf)) {
		t.Errorf("ParseFromVal(%q, %d, ..)=[%d, %d(%q)]  uri %q != %q (exp)",
			buf, offs, o, err, err, pf.URI.Get(buf), e.uri)
	}

	// compare the tag values taking into account whitespace
	if !bytescase.CmpEq(e.tag, pf.Tag.Get(buf)) {
		t.Errorf("ParseFromVal(%q, %d, ..)=[%d, %d(%q)]  tag %q != %q (exp)",
			buf, offs, o, err, err, pf.Tag.Get(buf), e.tag)
	}

	if !checkTSliceEq(e.params, pf.Params.Get(buf)) {
		t.Errorf("ParseFromVal(%q, %d, ..)=[%d, %d(%q)] params %q != %q (exp)",
			buf, offs, o, err, err, pf.Params.Get(buf), e.params)
	}
	if !bytes.Equal(e.v, pf.V.Get(buf)) {
		t.Errorf("ParseFromVal(%q, %d, ..)=[%d, %d(%q)]"+
			" trimmed body %q != %q (exp)",
			buf, offs, o, err, err, pf.V.Get(buf), e.v)
	}
	if !pf.Parsed() {
		t.Errorf("ParseFromVal(%q, %d, ..)=[%d, %d(%q)]"+
			" invalid/unexpected final state %d",
			buf, offs, o, err, err, pf.state)
	}
}

// check if 2 slices contain the same thing in case insensitive mode, after
// trimming whitespace
func checkTSliceEq(b1, b2 []byte) bool {
	return cmpCaseLWS(b1, b2)
	//return bytescase.CmpEq(bytes.TrimSpace(b1), bytes.TrimSpace(b2))
}

// skip over whitespace and return the number of ws chars skipped
// For now WS = [ \t], CR SP, LF SP or CR LF SP
func skipLWS2(b []byte) int {
	var i int
	for i < len(b) {
		switch b[i] {
		case ' ', '\t':
			i++
		case '\r', '\n':
			if (i + 1) < len(b) {
				switch b[i+1] {
				case ' ', '\t':
					i += 2 // CR SP or LF SP are considered WS
					continue
				case '\n': // CRLF SP  == WS (but not LF LF SP or LF CR SP)
					if b[i] == '\r' && (i+2) < len(b) &&
						(b[i+2] == ' ' || b[i+2] == '\t') {
						//CRLF SP is WS
						i += 3
						continue
					}
				}
				break
			}
		default:
			break
		}
	}
	return i
}

// compare 2 byte slices ingoring case and whitespace
func cmpCaseLWS(b1, b2 []byte) bool {

	lastCharDelim := false
	// skip WS at the beginning
	i, _, _ := skipLWS(b1, 0)
	j, _, _ := skipLWS(b2, 0)
	for (i < len(b1)) && (j < len(b2)) {
		ws1Len, _, _ := skipLWS(b1[i:], 0)
		ws2Len, _, _ := skipLWS(b2[j:], 0)
		// if WS in one and not in the other and the last non WS was
		// not a delim. (";")
		if ((ws1Len > 0) != (ws2Len > 0)) && !lastCharDelim {
			if ((i + ws1Len) < len(b1)) && ((j + ws2Len) < len(b2)) {
				if b1[i+ws1Len] == b2[j+ws2Len] && b1[i+ws1Len] == ';' {
					// allows "p ;m" to match "p;m"
					// and  "p;  m" to match "p;m" (lastCharDelim == true)
					i += ws1Len + 1
					j += ws2Len + 1
					lastCharDelim = true
					continue
				}
			}
			// fmt.Printf("fail0 %d/%d %d/%d %q <> %q\n", i, len(b1), j, len(b2), b1, b2)
			return false
		}
		i += ws1Len
		j += ws2Len
		if (i >= len(b1)) || (j >= len(b2)) {
			break
		}
		if (b1[i] >= 'A' && b1[i] <= 'Z') || (b1[i] >= 'a' && b1[i] <= 'z') {
			if b1[i]|0x20 != b2[j]|0x20 {
				// fmt.Printf("fail1: %d/%d %q %d/%d %q\n ", i, len(b1), i, len(b2), b1, b2)
				return false
			}
		} else if b1[i] != b2[j] {
			// fmt.Printf("fail2: %d/%d %q %d/%d %q %c!=%c\n ", i, len(b1), i, len(b2), b1, b2, b1[i], b2[j])
			return false
		}
		// equal non WS chars, check for delim
		lastCharDelim = (b1[i] == ';')
		i++
		j++
	}
	if i < len(b1) || j < len(b2) { // still chars left in one of the strs.
		// account for trailing whitespace (e.g: "ab" and "ab ")
		ws1Len, _, _ := skipLWS(b1[i:], 0)
		ws2Len, _, _ := skipLWS(b2[j:], 0)
		i += ws1Len
		j += ws2Len
		if i < len(b1) || j < len(b2) {
			// fmt.Printf("fail3 %d/%d %d/%d %q <> %q\n", i, len(b1), j, len(b2), b1, b2)
			return false
		}
	}
	return true
}

func randWS() string {
	ws := [...]string{"", " ", "	"}
	var s string
	n := rand.Intn(5) // max 5 whitespace "tokens"
	for i := 0; i < n; i++ {
		s += ws[rand.Intn(len(ws))]
	}
	return s
}

func randLWS() string {
	ws := [...]string{
		"", " ", "	", "\r\n ", "\r\n	", "\n ", "\r ",
	}
	var s string
	n := rand.Intn(5) // max 5 whitespace "tokens"
	for i := 0; i < n; i++ {
		s += ws[rand.Intn(len(ws))]
	}
	return s
}

// generate a from body from name, uri, params and tag value and
// returned the generated body + the params (since the params will also
// include the tag)
func genFromBody(n, u, p, tagv string, random bool) (string, string) {
	var s, params, tag string

	if len(n) == 0 {
		if random && (rand.Intn(2) == 0) {
			s = u
		} else {
			s = n + randLWS() + "<" + u + ">"
		}
	} else {
		s = n + randLWS() + "<" + u + ">"
	}
	if len(tagv) != 0 && len(p) != 0 {
		tag = "tag" + randLWS() + "=" + randLWS() + tagv
		//both param and tags present => random order
		if random && (rand.Intn(2) == 0) {
			params = p + randLWS() + ";" + randLWS() + tag
		} else {
			params = tag + randLWS() + ";" + randLWS() + p
		}
	} else if len(p) != 0 {
		params = p
	} else if len(tagv) != 0 {
		tag = "tag" + randLWS() + "=" + randLWS() + tagv
		params = tag
	}
	if len(params) != 0 {
		s += randLWS() + ";" + randLWS() + params
	}
	s += randLWS() // no end of header
	return s, params
}
