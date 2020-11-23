// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipsp

// ParseExpiresVal parses an Expires header value, starting at offs in buf.
// It returns a new offset pointing after the part that was parsed and an
// error.
// For more information see ParseUIntVal().
func ParseExpiresVal(buf []byte, offs int, pcl *PUIntBody) (int, ErrorHdr) {
	return ParseUIntVal(buf, offs, pcl)
}
