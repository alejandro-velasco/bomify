package xet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// referenceSHA256 is the reference CSV file's SHA-256.
const referenceSHA256 = "f41255b252f776125f2b657136654e4d4d5d2ccf8ef4db0ec186bd1981b69734"

// TestReferenceShard rebuilds the reference shard registering the CSV
// file from its chunks and SHA-256. Only the xorb's serialized size,
// which depends on its compression, comes from the reference.
func TestReferenceShard(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("testdata", "reference.shard"))
	if err != nil {
		t.Fatal(err)
	}
	reference, err := parseShard(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(reference.Files) != 1 || len(reference.Xorbs) != 1 {
		t.Fatalf("parsed %d files and %d xorbs, want 1 of each", len(reference.Files), len(reference.Xorbs))
	}

	sha256, err := hex.DecodeString(referenceSHA256)
	if err != nil {
		t.Fatal(err)
	}
	chunks := referenceChunks(t)
	var size uint64
	var offsets []uint32
	for _, chunk := range chunks {
		offsets = append(offsets, uint32(size))
		size += chunk.Size
	}
	xorb := xorbHash(chunks)
	file := fileEntry{
		Hash:   fileHash(chunks),
		SHA256: [32]byte(sha256),
		Terms: []term{{
			Xorb:         xorb,
			Start:        0,
			End:          uint32(len(chunks)),
			Size:         uint32(size),
			Verification: verificationHash(chunkHashes(chunks)),
		}},
	}
	listed := xorbEntry{
		Hash:           xorb,
		Chunks:         chunks,
		Offsets:        offsets,
		SerializedSize: reference.Xorbs[0].SerializedSize,
	}

	got := marshalShard([]fileEntry{file}, []xorbEntry{listed})
	if !bytes.Equal(got, want) {
		at := 0
		for at < min(len(got), len(want)) && got[at] == want[at] {
			at++
		}
		t.Errorf("marshalShard differs from the reference shard at byte %d (lengths %d and %d)", at, len(got), len(want))
	}
}

func TestParseShardFooter(t *testing.T) {
	key := Hash{1, 2, 3}
	listed := xorbEntry{
		Hash:           Hash{9},
		Chunks:         []chunk{{Hash: Hash{7}, Size: 10}},
		Offsets:        []uint32{0},
		SerializedSize: 18,
	}
	parsed, err := parseShard(withFooter(marshalShard(nil, []xorbEntry{listed}), key))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.HMACKey != key || len(parsed.Xorbs) != 1 || parsed.Xorbs[0].Chunks[0] != listed.Chunks[0] {
		t.Errorf("parseShard = %+v, want the xorb and HMAC key", parsed)
	}
}

func TestParseShardRefusesCorruption(t *testing.T) {
	valid := marshalShard(nil, []xorbEntry{{Hash: Hash{9}, Chunks: []chunk{{Size: 1}}, Offsets: []uint32{0}}})

	wrongTag := bytes.Clone(valid)
	wrongTag[0] = 'X'
	hugeCount := bytes.Clone(valid)
	// The xorb's chunk count, after the header and the file section's
	// bookend.
	binary.LittleEndian.PutUint32(hugeCount[2*shardEntrySize+36:], 1<<31)

	for name, data := range map[string][]byte{
		"empty":       nil,
		"wrong tag":   wrongTag,
		"truncated":   valid[:len(valid)-10],
		"huge count":  hugeCount,
		"header only": valid[:shardEntrySize],
	} {
		if _, err := parseShard(data); err == nil {
			t.Errorf("parseShard(%s) succeeded", name)
		}
	}
}

// withFooter adds a footer to an upload shard, as global deduplication
// answers have, holding the key their chunk hashes are HMAC'd with.
func withFooter(data []byte, key Hash) []byte {
	const footerSize = 200
	footer := make([]byte, footerSize)
	binary.LittleEndian.PutUint64(footer, 1) // version
	copy(footer[footerHMACKeyOffset:], key[:])
	binary.LittleEndian.PutUint64(footer[footerSize-8:], uint64(len(data)))

	shard := bytes.Clone(data)
	binary.LittleEndian.PutUint64(shard[40:], footerSize)
	return append(shard, footer...)
}
