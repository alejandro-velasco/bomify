package xet

// chunkHeaderSize is the size of the header before each chunk in a xorb.
const chunkHeaderSize = 8

// Limits on one xorb, from xorb.md and deduplication.md. Variables so
// tests can make them small.
var (
	maxXorbBytes  = 64 << 20
	maxXorbChunks = 8 << 10
)

// xorb is a xorb being filled: its chunks, serialized as xorb.md lays
// them out, each a header and its data, compressed.
type xorb struct {
	data   []byte
	chunks []chunk
	// offsets is where each chunk starts in the xorb's data uncompressed:
	// the sum of the sizes of the chunks before it.
	offsets []uint32
	// unpacked is the sum of all the chunks' sizes.
	unpacked uint32
}

// fits reports whether a chunk stored in size bytes fits in x.
func (x *xorb) fits(size int) bool {
	return len(x.chunks) < maxXorbChunks && len(x.data)+chunkHeaderSize+size <= maxXorbBytes
}

// add appends a chunk of size bytes, stored as stored with scheme, to x,
// and returns its index.
func (x *xorb) add(stored []byte, scheme byte, hash Hash, size int) uint32 {
	storedSize := len(stored)
	x.offsets = append(x.offsets, x.unpacked)
	x.unpacked += uint32(size)
	x.data = append(x.data,
		0, // version
		byte(storedSize), byte(storedSize>>8), byte(storedSize>>16),
		scheme,
		byte(size), byte(size>>8), byte(size>>16),
	)
	x.data = append(x.data, stored...)
	entry := chunk{
		Hash: hash,
		Size: uint64(size),
	}
	x.chunks = append(x.chunks, entry)
	return uint32(len(x.chunks) - 1)
}

// entry is x as a shard lists it, once it's hashed.
func (x *xorb) entry(hash Hash) xorbEntry {
	entry := xorbEntry{
		Hash:           hash,
		Chunks:         x.chunks,
		Offsets:        x.offsets,
		SerializedSize: uint32(len(x.data)),
	}
	return entry
}
