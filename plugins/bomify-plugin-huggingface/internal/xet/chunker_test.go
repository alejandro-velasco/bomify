package xet

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"slices"
	"testing"
	"testing/iotest"
)

// chunkAll returns every chunk of what reader reads.
func chunkAll(t *testing.T, reader io.Reader) [][]byte {
	t.Helper()
	chunker := newChunker(reader)
	var chunks [][]byte
	for {
		data, err := chunker.next()
		if errors.Is(err, io.EOF) {
			return chunks
		}
		if err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, bytes.Clone(data))
	}
}

func randomBytes(seed uint64, size int) []byte {
	random := rand.New(rand.NewPCG(seed, seed))
	data := make([]byte, size)
	for index := range data {
		data[index] = byte(random.Uint32())
	}
	return data
}

// TestChunkerReference chunks the reference CSV file (see
// testdata/README.md), 63 MB, so too big to keep in the repository: set
// XET_REFERENCE_CSV to where it's downloaded.
func TestChunkerReference(t *testing.T) {
	path := os.Getenv("XET_REFERENCE_CSV")
	if path == "" {
		t.Skip("XET_REFERENCE_CSV isn't set")
	}
	opened, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	want := referenceChunks(t)
	got := chunkAll(t, opened)
	if len(got) != len(want) {
		t.Fatalf("got %d chunks, want %d", len(got), len(want))
	}
	for index, data := range got {
		if uint64(len(data)) != want[index].Size || ChunkHash(data) != want[index].Hash {
			t.Fatalf("chunk %d is %d bytes, hash %s; want %d bytes, hash %s", index, len(data), ChunkHash(data), want[index].Size, want[index].Hash)
		}
	}
}

func TestChunkerBounds(t *testing.T) {
	data := randomBytes(1, 3<<20)
	chunks := chunkAll(t, bytes.NewReader(data))
	if len(chunks) < 10 {
		t.Fatalf("got %d chunks of 3 MiB, want about 48", len(chunks))
	}
	for index, chunk := range chunks {
		last := index == len(chunks)-1
		if len(chunk) > maxChunkSize || (len(chunk) < minChunkSize && !last) {
			t.Errorf("chunk %d is %d bytes", index, len(chunk))
		}
	}
	if !bytes.Equal(bytes.Join(chunks, nil), data) {
		t.Error("the chunks don't add up to the data")
	}

	// However the reader splits its reads, the chunks are the same.
	if !slices.EqualFunc(chunkAll(t, iotest.HalfReader(bytes.NewReader(data))), chunks, bytes.Equal) {
		t.Error("reading in small pieces changes the chunks")
	}
}

func TestChunkerSmallAndEmpty(t *testing.T) {
	if chunks := chunkAll(t, bytes.NewReader(nil)); len(chunks) != 0 {
		t.Errorf("an empty file has %d chunks, want none", len(chunks))
	}
	small := randomBytes(2, minChunkSize-1)
	if chunks := chunkAll(t, bytes.NewReader(small)); len(chunks) != 1 || !bytes.Equal(chunks[0], small) {
		t.Errorf("a file under %d bytes has %d chunks, want 1", minChunkSize, len(chunks))
	}
	// No boundary in zeros: every chunk is cut at the maximum.
	zeros := make([]byte, 3*maxChunkSize)
	for index, chunk := range chunkAll(t, bytes.NewReader(zeros)) {
		if len(chunk) != maxChunkSize {
			t.Errorf("chunk %d of zeros is %d bytes, want %d", index, len(chunk), maxChunkSize)
		}
	}
}

// TestChunkerLocality is why chunks are content-defined: inserting bytes
// changes only the chunks around them.
func TestChunkerLocality(t *testing.T) {
	data := randomBytes(3, 4<<20)
	edited := slices.Concat(data[:2<<20], []byte("inserted"), data[2<<20:])

	original := map[Hash]bool{}
	for _, chunk := range chunkAll(t, bytes.NewReader(data)) {
		original[ChunkHash(chunk)] = true
	}
	changed := 0
	for _, chunk := range chunkAll(t, bytes.NewReader(edited)) {
		if !original[ChunkHash(chunk)] {
			changed++
		}
	}
	if changed > 2 {
		t.Errorf("an 8-byte insertion changed %d chunks, want at most 2", changed)
	}
}

func TestChunkerReadError(t *testing.T) {
	failure := errors.New("disk on fire")
	chunker := newChunker(iotest.ErrReader(failure))
	if _, err := chunker.next(); !errors.Is(err, failure) {
		t.Errorf("next = %v, want %v", err, failure)
	}
}
