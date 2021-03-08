// Copyright 2019-2021 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

//+build nodebug

package sipsp

// logging functions, no debug version (empty, do nothing functions)

import ()

func init() {
	BuildTags = append(BuildTags, "nodebug")
}

// DBGon() is a shorthand for checking if generic debug logging is enabled
func DBGon() bool {
	return false
}

// DBG is a shorthand for logging a debug message.
func DBG(f string, a ...interface{}) {
}
