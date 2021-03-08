// Copyright 2019-2021 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipsp

// logging functions

import (
	"github.com/intuitivelabs/slog"
)

// Log is the generic log
var Log slog.Log = slog.New(slog.LERR, slog.LbackTraceL|slog.LlocInfoL,
	slog.LStdErr)

// WARN is a shorthand for logging a warning message.
func WARN(f string, a ...interface{}) {
	Log.LLog(slog.LWARN, 1, "WARNING: sipsp: ", f, a...)
}

// ERR is a shorthand for logging an error message.
func ERR(f string, a ...interface{}) {
	Log.LLog(slog.LERR, 1, "ERROR: sipsp: ", f, a...)
}

// BUG is a shorthand for logging a bug message.
func BUG(f string, a ...interface{}) {
	Log.LLog(slog.LBUG, 1, "BUG: sipsp: ", f, a...)
}
