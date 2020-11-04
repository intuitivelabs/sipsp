// // Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
// //
// // Use of this source code is governed by source-available license
// // that can be found in the LICENSE file in the root of the source
// // tree.

package sipsp

// ErrorHdr is the type for the errors returned by various header parsing
// functions. It implements the error interface. The zero value is by
// convention a non-error, so to convert from ErrorHdr to error one
// should use: if (errHdr == 0) { return nil } else { return errHdr }.
// (similar to syscall.Errno)
//
type ErrorHdr uint32

// Possible error value for header parsing functions.
const (
	ErrHdrOk         ErrorHdr = iota // no error, equiv. to nil
	ErrHdrEOH                        // header end
	ErrHdrEmpty                      // empty header (e.g. body start marker)
	ErrHdrMoreBytes                  // more input needed (premature end)
	ErrHdrMoreValues                 // more contacts, call again
	ErrHdrNoCR
	ErrHdrBadChar
	ErrHdrParams
	ErrHdrBad
	ErrHdrValNotNumber
	ErrHdrValTooLong
	ErrHdrValBad
	ErrHdrNumTooBig
	ErrHdrTrunc
	ErrHdrNoCLen // no Content-Length header and Content-Length required
	ErrHdrBug
	ErrConvBug
)

// error values corresp. to each ErrorHdr value: this way the interface
// allocations are done only once
// NOTE: keep in sync with the const above
var err2ErrorVal = [...]error{
	nil, // 0 corresp. to nil
	ErrHdrEOH,
	ErrHdrEmpty,
	ErrHdrMoreBytes, // more input needed (premature end)
	ErrHdrMoreValues,
	ErrHdrNoCR,
	ErrHdrBadChar,
	ErrHdrParams,
	ErrHdrBad,
	ErrHdrValNotNumber,
	ErrHdrValTooLong,
	ErrHdrValBad,
	ErrHdrNumTooBig,
	ErrHdrTrunc,
	ErrHdrNoCLen,
	ErrHdrBug,
	ErrConvBug,
}

var errHdrStr = [...]string{
	ErrHdrOk:           "no error",
	ErrHdrEmpty:        "empty header",
	ErrHdrEOH:          "end of header",
	ErrHdrMoreBytes:    "more bytes needed",
	ErrHdrMoreValues:   "more header values present",
	ErrHdrNoCR:         "CR expected",
	ErrHdrBadChar:      "invalid character in header",
	ErrHdrParams:       "error parsing header parameter",
	ErrHdrBad:          "bad header",
	ErrHdrValNotNumber: "header value is not a number",
	ErrHdrValTooLong:   "header value is too long",
	ErrHdrValBad:       "bad header value",
	ErrHdrNumTooBig:    "numeric header value too big",
	ErrHdrTrunc:        "incomplete/truncated data",
	ErrHdrNoCLen:       "no Content-Length header in message",
	ErrHdrBug:          "internal BUG while parsing header",
	ErrConvBug:         "error conversion BUG",
}

func (e ErrorHdr) Error() string {
	return errHdrStr[e]
}

// ErrorConv() converts the ErrorHdr value to error.
// It uses "boxed" values to prevent runtime allocations
func (e ErrorHdr) ErrorConv() error {
	if 0 <= int(e) && int(e) < len(err2ErrorVal) {
		return err2ErrorVal[e]
	}
	return ErrConvBug
}
