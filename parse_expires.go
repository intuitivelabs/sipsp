// // Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
// //
// // Use of this source code is governed by source-available license
// // that can be found in the LICENSE file in the root of the source
// // tree.

package sipsp

func ParseExpiresVal(buf []byte, offs int, pcl *PUIntBody) (int, ErrorHdr) {
	return ParseUIntVal(buf, offs, pcl)
}
