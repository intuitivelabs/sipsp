package calltr

// hash functions (for hash tables) ported from ser C versions (hashes.h)

func hashUpdate(h uint32, buf []byte, offs, l int) uint32 {
	end := offs + l
	i := offs
	for ; i <= end-4; i += 4 {
		v := (uint32(buf[i]) << 24) + (uint32(buf[i+1]) << 16) +
			(uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		h += v ^ (v >> 3)
	}
	var v uint32
	switch end - i {
	case 3:
		v = (uint32(buf[i]) << 16) + (uint32(buf[i+1]) << 8) + uint32(buf[i+2])
	case 2:
		v = (uint32(buf[i]) << 8) + uint32(buf[i+1])
	case 1:
		v = uint32(buf[i])
	}
	h += v ^ (v >> 3)
	return h
}

func hashFinish(h uint32) uint32 {
	return h + (h >> 11) + (h >> 13) + (h >> 23)
}

// slower then hash1Update but better distribution for numbers
func hash2Update(h uint32, buf []byte, offs, l int) uint32 {
	end := offs + l
	i := offs
	for ; i <= end-4; i += 4 {
		v := uint32(buf[i])*16777213 + uint32(buf[i+1])*65537 +
			uint32(buf[i+2])*257 + uint32(buf[i+3])
		h = 16777259*h + v ^ (v << 17)
	}
	var v uint32
	for ; i < end; i++ {
		v *= 251
		v += uint32(buf[i])
	}
	h = 16777259*h + v ^ (v << 17)
	return h
}

func hash2Finish(h uint32) uint32 {
	return h + (h >> 7) + (h >> 13) + (h >> 23)
}

// GetHash is a fast hash function optimized for strings.
// It will return the hash of  buf[offs:l].
// It should be used only for building hash tables (it has no
// cryptographic value).
// It's  ported from ser C version.
func GetHash(buf []byte, offs, l int) uint32 {
	var h uint32
	h = hashUpdate(h, buf, offs, l)
	return hashFinish(h)
}

// GetHash2 is similar to GetHash1 but a bit slower and with better
// distribution for number
func GetHash2(buf []byte, offs, l int) uint32 {
	var h uint32
	h = hash2Update(h, buf, offs, l)
	return hash2Finish(h)
}
