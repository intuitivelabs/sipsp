// Copyright 2019-2021 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

//+build default debug !nodebug

package sipsp

// logging functions, debug version

import (
	"github.com/intuitivelabs/slog"
)

func init() {
	BuildTags = append(BuildTags, "debug")
}

// DBGon() is a shorthand for checking if generic debug logging is enabled
func DBGon() bool {
	return Log.DBGon()
}

// DBG is a shorthand for logging a debug message.
func DBG(f string, a ...interface{}) {
	Log.LLog(slog.LDBG, 1, "DBG: sipsp:", f, a...)
}
