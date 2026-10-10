package xet

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The shard format, from shard.md: a header, then a section of file
// reconstructions and one of xorbs, each a series of 48-byte entries ended
// by a bookend, then (except in an upload) a footer.
const (
	shardEntrySize     = 48
	shardHeaderVersion = 2
	// footerHMACKeyOffset is where a footer holds the key its xorbs'
	// chunk hashes are HMAC'd with.
	footerHMACKeyOffset = 72

	fileFlagWithVerification = 1 << 31
	fileFlagWithMetadataExt  = 1 << 30
)

// maxShardBytes is the most one uploaded shard may hold. A variable so
// tests can make it small.
var maxShardBytes = 64 << 20

// shardTag starts every shard; shard.md leaves its value to xet-core's
// MDB_SHARD_HEADER_TAG.
var shardTag = [32]byte{
	'H', 'F', 'R', 'e', 'p', 'o', 'M', 'e', 't', 'a', 'D', 'a', 't', 'a', 0, 85,
	105, 103, 69, 106, 123, 129, 87, 131, 165, 189, 217, 92, 205, 209, 74, 169,
}

// bookend ends a shard's file and xorb sections: a hash of all 1 bits.
var bookend = Hash{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

// fileEntry is a file's reconstruction: its terms, in order, rebuild it.
type fileEntry struct {
	Hash Hash
	// SHA256 is the file's SHA-256, in its usual byte order. A shard
	// holds it as xet-core parses its hex: each 8-byte word reversed, as
	// in a Xet hash (see swapWords), which shard.md leaves out.
	SHA256 [32]byte
	Terms  []term
}

// term is a run of a file's chunks, chunks [Start, End) of a xorb, Size
// bytes unpacked.
type term struct {
	Xorb       Hash
	Start, End uint32
	Size       uint32
	// Verification is verificationHash of the run's chunk hashes.
	Verification Hash
}

// xorbEntry is a xorb as a shard lists it, for deduplication against.
type xorbEntry struct {
	Hash   Hash
	Chunks []chunk
	// Offsets is where each chunk starts in the xorb's data uncompressed,
	// which shard.md's "chunk_byte_range_start" leaves unclear: not where
	// its header is in the serialized xorb.
	Offsets []uint32
	// SerializedSize is the xorb's length as uploaded.
	SerializedSize uint32
}

func (f fileEntry) shardSize() int {
	// A header, then a term and a verification entry per term, then the
	// SHA-256.
	return shardEntrySize * (1 + 2*len(f.Terms) + 1)
}

func (x xorbEntry) shardSize() int {
	return shardEntrySize * (1 + len(x.Chunks))
}

// emptyShardSize is a shard's size with no files or xorbs: its header and
// two bookends.
const emptyShardSize = 3 * shardEntrySize

// marshalShard serializes files and xorbs into a shard to upload: with
// verification entries and each file's SHA-256, which the Hub's Git LFS
// pointers need, and without a footer.
func marshalShard(files []fileEntry, xorbs []xorbEntry) []byte {
	var data []byte
	data = append(data, shardTag[:]...)
	data = binary.LittleEndian.AppendUint64(data, shardHeaderVersion)
	data = binary.LittleEndian.AppendUint64(data, 0) // footer size

	for _, file := range files {
		data = append(data, file.Hash[:]...)
		data = binary.LittleEndian.AppendUint32(data, fileFlagWithVerification|fileFlagWithMetadataExt)
		data = binary.LittleEndian.AppendUint32(data, uint32(len(file.Terms)))
		data = append(data, make([]byte, 8)...)
		for _, term := range file.Terms {
			data = append(data, term.Xorb[:]...)
			data = binary.LittleEndian.AppendUint32(data, 0) // flags
			data = binary.LittleEndian.AppendUint32(data, term.Size)
			data = binary.LittleEndian.AppendUint32(data, term.Start)
			data = binary.LittleEndian.AppendUint32(data, term.End)
		}
		for _, term := range file.Terms {
			data = append(data, term.Verification[:]...)
			data = append(data, make([]byte, 16)...)
		}
		sha256 := swapWords(file.SHA256)
		data = append(data, sha256[:]...)
		data = append(data, make([]byte, 16)...)
	}
	data = appendBookend(data)

	for _, xorb := range xorbs {
		var unpacked uint32
		for _, chunk := range xorb.Chunks {
			unpacked += uint32(chunk.Size)
		}
		data = append(data, xorb.Hash[:]...)
		data = binary.LittleEndian.AppendUint32(data, 0) // flags
		data = binary.LittleEndian.AppendUint32(data, uint32(len(xorb.Chunks)))
		data = binary.LittleEndian.AppendUint32(data, unpacked)
		data = binary.LittleEndian.AppendUint32(data, xorb.SerializedSize)
		for index, chunk := range xorb.Chunks {
			data = append(data, chunk.Hash[:]...)
			data = binary.LittleEndian.AppendUint32(data, xorb.Offsets[index])
			data = binary.LittleEndian.AppendUint32(data, uint32(chunk.Size))
			data = append(data, make([]byte, 8)...)
		}
	}
	return appendBookend(data)
}

func appendBookend(data []byte) []byte {
	data = append(data, bookend[:]...)
	return append(data, make([]byte, 16)...)
}

// shard is a parsed shard.
type shard struct {
	Files []fileEntry
	Xorbs []xorbEntry
	// HMACKey, unless zero, is the key Xorbs' chunk hashes are HMAC'd with,
	// as a global deduplication answer hides them.
	HMACKey Hash
}

var errShortShard = errors.New("shard ends early")

// parseShard parses a shard, with or without its footer.
func parseShard(data []byte) (shard, error) {
	reader := shardReader{data: data}
	var parsed shard

	tag := reader.bytes(32)
	version := reader.uint64()
	footerSize := reader.uint64()
	if reader.err != nil {
		return shard{}, reader.err
	}
	if [32]byte(tag) != shardTag {
		return shard{}, errors.New("not a shard: wrong tag")
	}
	if version != shardHeaderVersion {
		return shard{}, fmt.Errorf("shard version %d, not %d", version, shardHeaderVersion)
	}
	if footerSize > uint64(len(data)) {
		return shard{}, errShortShard
	}

	for {
		hash := reader.hash()
		flags := reader.uint32()
		count := reader.uint32()
		reader.bytes(8)
		if reader.err != nil || hash == bookend {
			break
		}
		if !reader.has(count) {
			return shard{}, errShortShard
		}
		file := fileEntry{Hash: hash}
		for range count {
			entry := term{Xorb: reader.hash()}
			reader.uint32() // flags
			entry.Size = reader.uint32()
			entry.Start = reader.uint32()
			entry.End = reader.uint32()
			file.Terms = append(file.Terms, entry)
		}
		if flags&fileFlagWithVerification != 0 {
			for index := range file.Terms {
				file.Terms[index].Verification = reader.hash()
				reader.bytes(16)
			}
		}
		if flags&fileFlagWithMetadataExt != 0 {
			file.SHA256 = swapWords(reader.hash())
			reader.bytes(16)
		}
		parsed.Files = append(parsed.Files, file)
	}

	for {
		hash := reader.hash()
		reader.uint32() // flags
		count := reader.uint32()
		reader.uint32() // unpacked bytes
		serialized := reader.uint32()
		if reader.err != nil || hash == bookend {
			break
		}
		if !reader.has(count) {
			return shard{}, errShortShard
		}
		xorb := xorbEntry{
			Hash:           hash,
			SerializedSize: serialized,
		}
		for range count {
			entry := chunk{Hash: reader.hash()}
			xorb.Offsets = append(xorb.Offsets, reader.uint32())
			entry.Size = uint64(reader.uint32())
			reader.bytes(8)
			xorb.Chunks = append(xorb.Chunks, entry)
		}
		parsed.Xorbs = append(parsed.Xorbs, xorb)
	}
	if reader.err != nil {
		return shard{}, reader.err
	}

	if footerSize >= footerHMACKeyOffset+32 {
		footer := data[len(data)-int(footerSize):]
		parsed.HMACKey = Hash(footer[footerHMACKeyOffset : footerHMACKeyOffset+32])
	}
	return parsed, nil
}

// shardReader reads a shard's fields in order, failing every read after
// the data runs out.
type shardReader struct {
	data []byte
	err  error
}

func (r *shardReader) bytes(count int) []byte {
	if r.err != nil || len(r.data) < count {
		r.err = errShortShard
		return make([]byte, count)
	}
	field := r.data[:count]
	r.data = r.data[count:]
	return field
}

// has reports whether count more entries are left to read, so a corrupt
// count can't make a parse loop for long.
func (r *shardReader) has(count uint32) bool {
	return uint64(count)*shardEntrySize <= uint64(len(r.data))
}

func (r *shardReader) hash() Hash {
	return Hash(r.bytes(32))
}

func (r *shardReader) uint32() uint32 {
	return binary.LittleEndian.Uint32(r.bytes(4))
}

func (r *shardReader) uint64() uint64 {
	return binary.LittleEndian.Uint64(r.bytes(8))
}
