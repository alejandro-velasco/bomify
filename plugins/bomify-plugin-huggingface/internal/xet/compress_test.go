package xet

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/rand/v2"
	"os"
	"testing"
)

func TestByteGroup(t *testing.T) {
	data := []byte{'a', 'b', 'c', 'd', 'A', 'B', 'C', 'D', '1', '2'}
	if got, want := byteGroup(data), []byte("aA1bB2cCdD"); !bytes.Equal(got, want) {
		t.Errorf("byteGroup = %q, want %q", got, want)
	}
	for size := range 9 {
		data := randomBytes(uint64(size), size)
		if got := byteUngroup(byteGroup(data)); !bytes.Equal(got, data) {
			t.Errorf("byteUngroup(byteGroup(%d bytes)) = %v, want %v", size, got, data)
		}
	}
}

// TestCompress checks each chunk is stored with whichever scheme is
// smallest, and decompresses to itself.
func TestCompress(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 1))
	weights := make([]byte, 0, 64<<10)
	for range 16 << 10 {
		weights = binary.LittleEndian.AppendUint32(weights, math.Float32bits(float32(random.IntN(64)-32)/8))
	}
	text := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog. "), 1500)

	compressor := newCompressor()
	for name, data := range map[string][]byte{
		"weights": weights,
		"text":    text,
		"random":  randomBytes(15, 64<<10),
	} {
		var plain, grouped bytes.Buffer
		if err := compressor.frame(&plain, data); err != nil {
			t.Fatal(err)
		}
		if err := compressor.frame(&grouped, byteGroup(data)); err != nil {
			t.Fatal(err)
		}
		stored, scheme, err := compressor.compress(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if smallest := min(len(data), plain.Len(), grouped.Len()); len(stored) != smallest {
			t.Errorf("%s stored in %d bytes with scheme %d; the smallest is %d", name, len(stored), scheme, smallest)
		}
		got, err := decompress(scheme, bytes.Clone(stored), len(data))
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("%s doesn't decompress to itself: %v", name, err)
		}
	}

	// Byte-grouped LZ4 decompresses to itself too, whatever compress
	// picked above.
	var grouped bytes.Buffer
	if err := compressor.frame(&grouped, byteGroup(weights[:1001])); err != nil {
		t.Fatal(err)
	}
	if got, err := decompress(compressionBG4LZ4, grouped.Bytes(), 1001); err != nil || !bytes.Equal(got, weights[:1001]) {
		t.Errorf("byte-grouped LZ4 doesn't decompress to itself: %v", err)
	}
}

// TestReferenceXorb decompresses the reference xorb, which xet-core
// wrote with LZ4 frames, into the reference chunks: proof this package
// writes the same format it reads. It's 14 MB, so too big to keep in the
// repository: set XET_REFERENCE_XORB to where it's downloaded (see
// testdata/README.md).
func TestReferenceXorb(t *testing.T) {
	path := os.Getenv("XET_REFERENCE_XORB")
	if path == "" {
		t.Skip("XET_REFERENCE_XORB isn't set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := referenceChunks(t)
	got, err := decodeChunks(data[:len(data)-trailingXorbBytes(t, data, len(want))], len(want))
	if err != nil {
		t.Fatal(err)
	}
	for index, chunk := range got {
		if ChunkHash(chunk) != want[index].Hash {
			t.Fatalf("chunk %d hashes to %s, want %s", index, ChunkHash(chunk), want[index].Hash)
		}
	}
}

// trailingXorbBytes is how many bytes follow the reference xorb's count
// chunks: it ends with 4 that aren't part of any.
func trailingXorbBytes(t *testing.T, data []byte, count int) int {
	t.Helper()
	at := 0
	for range count {
		at += chunkHeaderSize + (int(data[at+1]) | int(data[at+2])<<8 | int(data[at+3])<<16)
	}
	return len(data) - at
}
