package sipsp

func ParseExpiresVal(buf []byte, offs int, pcl *PUIntBody) (int, ErrorHdr) {
	return ParseUIntVal(buf, offs, pcl)
}
