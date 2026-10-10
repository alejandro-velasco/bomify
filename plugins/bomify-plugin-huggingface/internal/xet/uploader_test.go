package xet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeCAS is a CAS server checking what it's sent as the real one would:
// that each xorb is well formed and has the hash it's uploaded under, and
// that a shard is well formed, references only uploaded xorbs, lists
// their chunks' offsets, and proves each term with its verification hash. It answers global deduplication
// queries for a chunk it holds with every xorb it knows of, their chunk
// hashes HMAC'd with Key.
type fakeCAS struct {
	Key Hash
	// FailXorbs fails every xorb upload.
	FailXorbs bool

	mutex sync.Mutex
	// xorbs holds each uploaded xorb's chunks.
	xorbs map[Hash][][]byte
	// listed holds the xorbs shards listed, and files the files they
	// registered.
	listed  []xorbEntry
	files   map[Hash]fileEntry
	queries int
}

func newFakeCAS() *fakeCAS {
	cas := fakeCAS{
		Key:   Hash{0x12, 0x34},
		xorbs: map[Hash][][]byte{},
		files: map[Hash]fileEntry{},
	}
	return &cas
}

func (f *fakeCAS) UploadXorb(_ context.Context, hash Hash, data []byte) error {
	if f.FailXorbs {
		return errors.New("storage is full")
	}
	if len(data) > maxXorbBytes {
		return fmt.Errorf("xorb is %d bytes, over %d", len(data), maxXorbBytes)
	}
	chunks, err := decodeXorb(data)
	if err != nil {
		return err
	}
	var listed []chunk
	for _, content := range chunks {
		listed = append(listed, chunk{Hash: ChunkHash(content), Size: uint64(len(content))})
	}
	if got := xorbHash(listed); got != hash {
		return fmt.Errorf("xorb uploaded as %s hashes to %s", hash, got)
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.xorbs[hash] = chunks
	return nil
}

func (f *fakeCAS) UploadShard(_ context.Context, data []byte) error {
	parsed, err := parseShard(data)
	if err != nil {
		return err
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	for _, file := range parsed.Files {
		for _, term := range file.Terms {
			chunks, ok := f.xorbs[term.Xorb]
			if !ok {
				return fmt.Errorf("file %s needs xorb %s, which isn't uploaded", file.Hash, term.Xorb)
			}
			if term.End > uint32(len(chunks)) || term.Start >= term.End {
				return fmt.Errorf("term [%d, %d) is outside xorb %s", term.Start, term.End, term.Xorb)
			}
			var hashes []Hash
			var size uint32
			for _, data := range chunks[term.Start:term.End] {
				hashes = append(hashes, ChunkHash(data))
				size += uint32(len(data))
			}
			if term.Size != size || term.Verification != verificationHash(hashes) {
				return fmt.Errorf("term [%d, %d) of xorb %s doesn't verify", term.Start, term.End, term.Xorb)
			}
		}
		f.files[file.Hash] = file
	}
	for _, xorb := range parsed.Xorbs {
		chunks, ok := f.xorbs[xorb.Hash]
		if !ok {
			return fmt.Errorf("shard lists xorb %s, which isn't uploaded", xorb.Hash)
		}
		// Each chunk starts where the ones before it end, uncompressed.
		var offset uint32
		for index, data := range chunks {
			if index >= len(xorb.Offsets) || xorb.Offsets[index] != offset {
				return fmt.Errorf("shard lists xorb %s's chunk %d at the wrong offset", xorb.Hash, index)
			}
			offset += uint32(len(data))
		}
	}
	f.listed = append(f.listed, parsed.Xorbs...)
	return nil
}

func (f *fakeCAS) QueryChunk(_ context.Context, hash Hash) ([]byte, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.queries++
	held := false
	var hidden []xorbEntry
	for _, xorb := range f.listed {
		entry := xorb
		entry.Chunks = nil
		for _, listed := range xorb.Chunks {
			held = held || listed.Hash == hash
			entry.Chunks = append(entry.Chunks, chunk{Hash: listed.Hash.hmac(f.Key), Size: listed.Size})
		}
		hidden = append(hidden, entry)
	}
	if !held {
		return nil, nil
	}
	return withFooter(marshalShard(nil, hidden), f.Key), nil
}

// rebuild rebuilds the file registered under hash from its xorbs.
func (f *fakeCAS) rebuild(t *testing.T, hash Hash) ([]byte, [32]byte) {
	t.Helper()
	f.mutex.Lock()
	defer f.mutex.Unlock()
	file, ok := f.files[hash]
	if !ok {
		t.Fatalf("file %s isn't registered", hash)
	}
	var data []byte
	for _, term := range file.Terms {
		for _, chunk := range f.xorbs[term.Xorb][term.Start:term.End] {
			data = append(data, chunk...)
		}
	}
	return data, file.SHA256
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// smallXorbs makes xorbs hold at most size bytes, for the test.
func smallXorbs(t *testing.T, size int) {
	original := maxXorbBytes
	maxXorbBytes = size
	t.Cleanup(func() { maxXorbBytes = original })
}

func upload(t *testing.T, cas CAS, files ...[]byte) []Added {
	t.Helper()
	uploader := NewUploader(context.Background(), cas, discardLogger())
	var added []Added
	for _, data := range files {
		result, err := uploader.Add(bytes.NewReader(data), sha256.Sum256(data))
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
		added = append(added, result)
	}
	if err := uploader.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return added
}

func TestUploaderRoundTrip(t *testing.T) {
	cas := newFakeCAS()
	original := randomBytes(4, 3<<20)
	// A file sharing most of original: only the chunks around the
	// replaced middle are new.
	edited := slices.Concat(original[:1<<20], randomBytes(5, 300<<10), original[2<<20:])
	small := []byte("a file of one small chunk")

	added := upload(t, cas, original, edited, small, original)

	for index, data := range [][]byte{original, edited, small, original} {
		rebuilt, sum := cas.rebuild(t, added[index].Hash)
		if !bytes.Equal(rebuilt, data) || sum != sha256.Sum256(data) {
			t.Errorf("file %d doesn't rebuild from its xorbs, or has the wrong SHA-256", index)
		}
		if added[index].Size != int64(len(data)) {
			t.Errorf("file %d: Size = %d, want %d", index, added[index].Size, len(data))
		}
	}
	if added[0].NewBytes != int64(len(original)) {
		t.Errorf("the first file stored %d new bytes, want all %d", added[0].NewBytes, len(original))
	}
	if newBytes := added[1].NewBytes; newBytes == 0 || newBytes > 600<<10 {
		t.Errorf("the edited file stored %d new bytes, want about the 300 KiB replaced", newBytes)
	}
	if added[3].NewBytes != 0 || added[3].Hash != added[0].Hash {
		t.Errorf("the repeated file stored %d new bytes, want none, under the same hash", added[3].NewBytes)
	}
	if len(cas.files) != 3 {
		t.Errorf("registered %d files, want 3", len(cas.files))
	}
}

func TestUploaderGlobalDedupe(t *testing.T) {
	cas := newFakeCAS()
	original := randomBytes(6, 2<<20)
	upload(t, cas, original)
	uploaded := len(cas.xorbs)

	// A new upload, with nothing of its own stored yet, finds every chunk
	// through global deduplication.
	added := upload(t, cas, original)
	if added[0].NewBytes != 0 || len(cas.xorbs) != uploaded {
		t.Errorf("uploading again stored %d new bytes in %d new xorbs, want none", added[0].NewBytes, len(cas.xorbs)-uploaded)
	}
	if rebuilt, _ := cas.rebuild(t, added[0].Hash); !bytes.Equal(rebuilt, original) {
		t.Error("the deduplicated file doesn't rebuild")
	}
	if cas.queries == 0 {
		t.Error("no global deduplication query")
	}
}

func TestUploaderSkipsBrokenDedupe(t *testing.T) {
	data := randomBytes(7, 100<<10)
	cas := &brokenDedupeCAS{fakeCAS: newFakeCAS()}
	added := upload(t, cas, data)
	if added[0].NewBytes != int64(len(data)) {
		t.Errorf("stored %d new bytes, want all %d", added[0].NewBytes, len(data))
	}
}

// brokenDedupeCAS answers global deduplication with garbage.
type brokenDedupeCAS struct {
	*fakeCAS
}

func (*brokenDedupeCAS) QueryChunk(context.Context, Hash) ([]byte, error) {
	return []byte("not a shard"), nil
}

func TestUploaderXorbFailure(t *testing.T) {
	cas := newFakeCAS()
	cas.FailXorbs = true
	uploader := NewUploader(context.Background(), cas, discardLogger())
	data := randomBytes(8, 1<<20)
	if _, err := uploader.Add(bytes.NewReader(data), sha256.Sum256(data)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := uploader.Finish(); err == nil || !strings.Contains(err.Error(), "storage is full") {
		t.Errorf("Finish = %v, want the xorb upload's error", err)
	}
	if len(cas.files) != 0 {
		t.Error("a file was registered without its xorbs")
	}
}

func TestUploaderReadFailure(t *testing.T) {
	uploader := NewUploader(context.Background(), newFakeCAS(), discardLogger())
	reader := io.MultiReader(bytes.NewReader(randomBytes(9, 1<<20)), failingReader{})
	if _, err := uploader.Add(reader, [32]byte{}); err == nil {
		t.Error("Add succeeded reading a failing file")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("disk on fire")
}

func TestShardBatches(t *testing.T) {
	original := maxShardBytes
	maxShardBytes = 20 * shardEntrySize
	t.Cleanup(func() { maxShardBytes = original })

	files := make([]fileEntry, 5)
	for index := range files {
		files[index] = fileEntry{Hash: Hash{byte(index)}, Terms: make([]term, 2)}
	}
	xorbs := make([]xorbEntry, 4)
	for index := range xorbs {
		xorbs[index] = xorbEntry{Hash: Hash{byte(index)}, Chunks: make([]chunk, 6), Offsets: make([]uint32, 6)}
	}

	batches := shardBatches(files, xorbs)
	var gotFiles, gotXorbs int
	for index, batch := range batches {
		size := len(marshalShard(batch.files, batch.xorbs))
		if size > maxShardBytes {
			t.Errorf("shard %d is %d bytes, over %d", index, size, maxShardBytes)
		}
		gotFiles += len(batch.files)
		gotXorbs += len(batch.xorbs)
	}
	if gotFiles != len(files) || gotXorbs != len(xorbs) || len(batches) < 3 {
		t.Errorf("%d shards hold %d files and %d xorbs, want all %d and %d over several", len(batches), gotFiles, gotXorbs, len(files), len(xorbs))
	}
}

// TestShardEntrySizes keeps shardSize in step with marshalShard.
func TestShardEntrySizes(t *testing.T) {
	file := fileEntry{Terms: make([]term, 3)}
	xorb := xorbEntry{Chunks: make([]chunk, 5), Offsets: make([]uint32, 5)}
	if got, want := len(marshalShard([]fileEntry{file}, []xorbEntry{xorb})), emptyShardSize+file.shardSize()+xorb.shardSize(); got != want {
		t.Errorf("shard is %d bytes, shardSize adds up to %d", got, want)
	}
	if got := binary.LittleEndian.Uint64(marshalShard(nil, nil)[40:]); got != 0 {
		t.Errorf("footer size = %d, want 0: an uploaded shard has none", got)
	}
}

func TestUploaderSplitsXorbs(t *testing.T) {
	smallXorbs(t, 512<<10)
	cas := newFakeCAS()
	data := randomBytes(10, 3<<20)
	added := upload(t, cas, data)
	if rebuilt, _ := cas.rebuild(t, added[0].Hash); !bytes.Equal(rebuilt, data) {
		t.Error("the file doesn't rebuild from its xorbs")
	}
	if len(cas.xorbs) < 6 {
		t.Errorf("uploaded %d xorbs, want at least 6 of at most 512 KiB", len(cas.xorbs))
	}
}

// TestUploaderStoresShortRunsAgain checks fragmentation prevention: a
// file sharing only a few chunks with another stores them again, in
// order with its own, rather than pointing back into the other's xorb.
func TestUploaderStoresShortRunsAgain(t *testing.T) {
	cas := newFakeCAS()
	shared := randomBytes(11, 2<<20)
	// The middle of shared between new data: once chunking finds its
	// boundaries in it again, a run of about 3 chunks matches.
	mixed := slices.Concat(randomBytes(12, 1<<20), shared[800<<10:1000<<10], randomBytes(13, 1<<20))

	added := upload(t, cas, shared, mixed)
	if added[1].NewBytes != added[1].Size {
		t.Errorf("the mixed file stored %d of its %d bytes, want all of them", added[1].NewBytes, added[1].Size)
	}
	if terms := cas.files[added[1].Hash].Terms; len(terms) != 1 {
		t.Errorf("the mixed file has %d terms, want 1: its chunks in order", len(terms))
	}
	if rebuilt, _ := cas.rebuild(t, added[1].Hash); !bytes.Equal(rebuilt, mixed) {
		t.Error("the mixed file doesn't rebuild")
	}
}

// TestUploaderReusesSmallWholeFile checks a file shorter than
// minDedupeRun chunks is still reused whole.
func TestUploaderReusesSmallWholeFile(t *testing.T) {
	cas := newFakeCAS()
	data := randomBytes(14, 200<<10)
	added := upload(t, cas, data, data)
	if added[1].NewBytes != 0 {
		t.Errorf("the repeated small file stored %d new bytes, want none", added[1].NewBytes)
	}
}
