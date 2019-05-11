package sipsp

//OffsT is the type used for offset and length used internally in PField.
type OffsT uint16 // TODO: change to uint16 (once max buf & msg size <= 65k)

// PField is the type for parsed fields (like host, to body a.s.o.)
type PField struct {
	Offs OffsT
	Len  OffsT
}

// Set sets a PField to point to [start:end]
func (p *PField) Set(start, end int) {
	p.Offs = OffsT(start)
	p.Len = OffsT(end - start)
}

// Reset sets a PField to the empty value.
func (p *PField) Reset() {
	p.Offs = 0
	p.Len = 0
}

// Extend "grows" a PField to a new end offset.
func (p *PField) Extend(newEnd int) {
	p.Len = OffsT(newEnd) - p.Offs
}

func (p PField) Empty() bool {
	return p.Len == 0
}

func (p PField) Get(buf []byte) []byte {
	return GetPField(buf, p)
}

//GetPField returns a byte slice for the corresp. field f, pointing inside buf.
func GetPField(buf []byte, f PField) []byte {
	return buf[f.Offs : f.Offs+f.Len]
}
