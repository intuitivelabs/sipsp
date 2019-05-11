package bytescase

import (
	"bytes"
	"flag"
	"log"
	"math/rand"
	"os"
	"testing"
	"unsafe"
)

var cfgIterations uint = 1000
var cfgStrMinLen uint = 1
var cfgStrMaxLen uint = 255
var cfgMinChr uint = 0
var cfgMaxChr uint = 255

func TestMain(m *testing.M) {
	// parse extra cmd. line args
	flag.UintVar(&cfgIterations, "iterations", 1000,
		"number of test iterations")
	flag.UintVar(&cfgStrMinLen, "min_str_len", 1,
		"minimum generated string length")
	flag.UintVar(&cfgStrMaxLen, "max_str_len", 255,
		"maximum generated string length")
	flag.UintVar(&cfgMinChr, "char_range_start", 0,
		"start of character range (number, inclusive)")
	flag.UintVar(&cfgMaxChr, "char_range_end", 255,
		"end of character range (number, inclusive)")
	flag.Parse()
	log.Printf("using -iterations %d\n", cfgIterations)
	log.Printf("      string size between %d - %d\n",
		cfgStrMinLen, cfgStrMaxLen)
	log.Printf("      character set: [%d - %d]\n", cfgMinChr, cfgMaxChr)
	// sanity checks
	if cfgStrMinLen > cfgStrMaxLen {
		log.Fatalf("invalid string length range: %d : %d\n",
			cfgStrMinLen, cfgStrMaxLen)
	}
	if (cfgMinChr > cfgMaxChr) || (cfgMaxChr > 255) {
		log.Fatalf("invalid character length range: %d : %d\n",
			cfgMinChr, cfgMaxChr)
	}

	res := m.Run()
	os.Exit(res)
}

func genRandStr(len int, minchr, maxchr byte) []byte {
	var b []byte = make([]byte, len)

	for i := 0; i < len; i++ {
		b[i] = byte(rand.Intn(int(maxchr)-int(minchr)+1)) + minchr
	}
	return b
}

// generate 2 random strings of the same lenght with
// random case differences
func gen2RandCaseStr(len int, minchr, maxchr byte) ([]byte, []byte) {
	var b1 []byte = make([]byte, len)
	var b2 []byte = make([]byte, len)

	for i := 0; i < len; i++ {
		b1[i] = byte(rand.Intn(int(maxchr)-int(minchr)+1)) + minchr
		if (b1[i] >= 'A' && b1[i] <= 'Z') && rand.Intn(2) != 0 {
			b2[i] = b1[i] - 'A' + 'a'
		} else if (b1[i] >= 'a' && b1[i] <= 'z') && rand.Intn(2) != 0 {
			b2[i] = b1[i] - 'a' + 'A'
		} else {
			b2[i] = b1[i]
		}
	}
	return b1, b2
}

func TestByteToLowerRand(t *testing.T) {
	for i := uint(0); i < cfgIterations; i++ {
		slen := rand.Intn(int(cfgStrMaxLen-cfgStrMinLen+1)) + int(cfgStrMinLen)
		s := genRandStr(slen, byte(cfgMinChr), byte(cfgMaxChr))
		for _, b := range s {
			if ByteToLower(b) != tByteToLower(b) {
				t.Errorf("test failed for %x (%+q)\n", b, b)
			}
		}
	}
}

func TestByteToUpperRand(t *testing.T) {
	for i := uint(0); i < cfgIterations; i++ {
		slen := rand.Intn(int(cfgStrMaxLen-cfgStrMinLen+1)) + int(cfgStrMinLen)
		s := genRandStr(slen, byte(cfgMinChr), byte(cfgMaxChr))
		for _, b := range s {
			if ByteToUpper(b) != tByteToUpper(b) {
				t.Errorf("test failed for %x (%+q)\n", b, b)
			}
		}
	}
}

func TestToLower(t *testing.T) {
	// subtests
	t.Run("fixed", testToLowerFixed)
	t.Run("random", testToLowerRand)
}

func testToLowerRand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode (-test.short used)")
	}
	for i := uint(0); i < cfgIterations; i++ {
		slen := rand.Intn(int(cfgStrMaxLen-cfgStrMinLen+1)) + int(cfgStrMinLen)
		s := genRandStr(slen, byte(cfgMinChr), byte(cfgMaxChr))
		testToLowerStr(t, s)
	}
}

func testToLowerFixed(t *testing.T) {
	str := "Test Lower Case conversion 12345 ,._\xc4\n"
	testToLowerStr(t, []byte(str))
}

func testToLowerStr(t *testing.T, src []byte) {
	var res []byte = make([]byte, len(src))

	err := ToLower(src[:], res[:])
	if err != nil {
		t.Fatalf("ToLower(%+q) error %s", string(src), err)
	}
	var res2 []byte = make([]byte, len(src))
	err = tToLower(src[:], res2[:])
	if err != nil {
		t.Fatalf("internal tToLower(%+q) error %s", string(src), err)
	}
	if !bytes.Equal(res[:], res2[:]) {
		t.Errorf("ToLower(%+q): bytes.ToLower check failed: %+q != %+q",
			string(src), res, res2)
	}

	// run tests using bytesToLower only if our string does not contain any
	// unicode (otherwise the result will be different)
	for _, v := range src {
		if v >= 128 {
			// unicode char ...
			return
		}
	}
	chk := bytes.ToLower(src[:])
	if !bytes.Equal(res[:], chk) {
		t.Errorf("ToLower(%+q): bytes.ToLower check2 failed: %+q != %+q",
			string(src), res, chk)
	}
}

func benchmarkToLowerRandInit(b *testing.B) [][]byte {
	// maximum strings created per benchmark: 1MB max mem used
	maxStrs := (1024*1024*1024)/int(cfgStrMaxLen) + 1
	/*
		if maxStrs > b.N {
			maxStrs = b.N
		}
	*/
	if maxStrs > int(cfgIterations) {
		maxStrs = int(cfgIterations)
	}
	if maxStrs <= 0 {
		maxStrs = 1
	}
	log.Printf("	generating %d random string(s)...(%d)\n", maxStrs, b.N)
	var s [][]byte = make([][]byte, maxStrs)
	for n := 0; n < maxStrs; n++ {
		s[n] = genRandStr(int(cfgStrMaxLen), byte(cfgMinChr), byte(cfgMaxChr))
	}
	return s
}

func benchmarkToLowerRand(b *testing.B, tolower func(s, d []byte) error, s [][]byte, tmp []byte) {
	b.ResetTimer()
	cnt := 0
	var err bool = false
	var r, i int
	for r = 0; r < b.N/len(s); r++ {
		for i := 0; i < len(s); i++ {
			err = err || tolower(s[i][:], tmp[:]) != nil
			cnt++
		}
	}
	for i = 0; i < b.N%len(s); i++ {
		err = err || tolower(s[i][:], tmp[:]) != nil
		cnt++
	}
	b.StopTimer()
	log.Printf(" %d(%d*%d+%d)/%d benchmark runs, errors %v\n", cnt, r, len(s), i, b.N, err)
}

func BenchmarkToLowerRand(b *testing.B) {
	log.Printf("benchmark starting...\n")
	s := benchmarkToLowerRandInit(b)
	var tmp []byte = make([]byte, cfgStrMaxLen)
	b.Run("bytescase.ToLower",
		func(b *testing.B) { benchmarkToLowerRand(b, ToLower, s, tmp) })
	b.Run("classic toLower",
		func(b *testing.B) { benchmarkToLowerRand(b, tToLower, s, tmp) })
}

func TestCmpEqRand(t *testing.T) {
	for i := uint(0); i < cfgIterations; i++ {
		slen := rand.Intn(int(cfgStrMaxLen-cfgStrMinLen+1)) + int(cfgStrMinLen)
		s1, s2 := gen2RandCaseStr(slen, byte(cfgMinChr), byte(cfgMaxChr))
		testCmpEq(t, s1, s2, true)
		s2[rand.Intn(len(s2))]++    //randomly change 1 char
		testCmpEq(t, s1, s2, false) // check if it fails
	}
}

func testCmpEq(t *testing.T, s1, s2 []byte, res bool) {
	//res := tCmpEq(s1, s2)
	if CmpEq(s1, s2) != res {
		t.Errorf("CmpEq(%+q, %+q) check failed, expected %t", s1, s2, res)
	}
}

func benchCmpEq(b *testing.B, bcmpeq func(a, b []byte) bool, s1, s2 []byte) {
	var t bool
	var cnt int
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t = bcmpeq(s1, s2)
		cnt += *((*int)(unsafe.Pointer(&t))) & 1
	}
	b.StopTimer()
	log.Printf("  %d / %d succesfull compares\n", cnt, b.N)
}

func BenchmarkCmpEqRand(b *testing.B) {
	// init
	slen := rand.Intn(int(cfgStrMaxLen-cfgStrMinLen+1)) + int(cfgStrMinLen)
	s1, s2 := gen2RandCaseStr(slen, byte(cfgMinChr), byte(cfgMaxChr))
	s3 := make([]byte, len(s2))
	copy(s3, s2)
	s3[rand.Intn(len(s3))]++ //randomly change 1 char
	b.Run("bytescase.CmpEq true",
		func(b *testing.B) { benchCmpEq(b, CmpEq, s1, s2) })
	b.Run("bytescase.CmpEq false",
		func(b *testing.B) { benchCmpEq(b, CmpEq, s1, s3) })
	b.Run("bytescase.tCmpEq true",
		func(b *testing.B) { benchCmpEq(b, tCmpEq, s1, s2) })
	b.Run("bytescase.tCmpEq false",
		func(b *testing.B) { benchCmpEq(b, tCmpEq, s1, s3) })
	b.Run("bytes.EqualFold true",
		func(b *testing.B) { benchCmpEq(b, bytes.EqualFold, s1, s2) })
	b.Run("bytes.EqualFold false",
		func(b *testing.B) { benchCmpEq(b, bytes.EqualFold, s1, s3) })
}

func TestPrefixRand(t *testing.T) {
	for i := uint(0); i < cfgIterations; i++ {
		slen := rand.Intn(int(cfgStrMaxLen-cfgStrMinLen+1)) + int(cfgStrMinLen)
		s1, s2 := gen2RandCaseStr(slen, byte(cfgMinChr), byte(cfgMaxChr))
		for i := 0; i < slen; i++ {
			testPrefix(t, s1[:i], s2, i, true)
		}
		for i := 2; i < slen; i++ {
			idx := rand.Intn(len(s2))
			s2[idx]++                         //randomly change 1 char
			testPrefix(t, s1, s2, idx, false) // check if it fails
			s2[idx]--                         //restore value
		}
	}
}

func testPrefix(t *testing.T, s1, s2 []byte, res1 int, res2 bool) {
	idx, match := Prefix(s1, s2)
	if match != res2 {
		t.Errorf("Prefix(%+q, %+q) match failed, expected %t", s1, s2, res2)
	}
	if idx != res1 {
		t.Errorf("Prefix(%+q, %+q) 1st non matching idex is wrong %d!=%d",
			s1, s2, idx, res1)
	}
}
