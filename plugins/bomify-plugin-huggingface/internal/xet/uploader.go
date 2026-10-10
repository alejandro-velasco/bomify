package xet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"golang.org/x/sync/errgroup"
)

// CAS is the Xet storage server an Uploader sends to (see api.md).
type CAS interface {
	// UploadXorb uploads a serialized xorb.
	UploadXorb(ctx context.Context, hash Hash, data []byte) error
	// UploadShard uploads a shard, registering its files.
	UploadShard(ctx context.Context, data []byte) error
	// QueryChunk asks global deduplication about a chunk, returning its
	// answer, a shard, or nil if no xorb the server knows of holds it.
	QueryChunk(ctx context.Context, chunk Hash) ([]byte, error)
}

// concurrentXorbUploads is how many xorbs an Uploader uploads at once,
// each up to maxXorbBytes held in memory.
const concurrentXorbUploads = 4

// globalDedupeEvery decides which chunks an Uploader asks global
// deduplication about, besides each file's first: those whose hash's last
// word is a multiple of it (see deduplication.md).
const globalDedupeEvery = 1024

// Uploader uploads files to a CAS. Each file's chunks are deduplicated
// against what this upload already stored, and against the whole server
// (global deduplication); the rest are packed into xorbs, uploaded as
// they fill. Finish uploads the last xorb, then the shards registering
// the files, which only then exist on the server.
type Uploader struct {
	// ctx bounds the upload, and uploadCtx the xorb uploads in group,
	// canceled when one fails.
	ctx       context.Context
	uploadCtx context.Context
	cas       CAS
	logger    *slog.Logger
	group     *errgroup.Group
	// compressor compresses the chunks stored.
	compressor *compressor

	// xorbs are every xorb a file's terms point into: this upload's, and
	// others global deduplication found.
	xorbs     []*xorbSlot
	xorbIndex map[Hash]int
	// current is the xorb being filled, xorbs[currentSlot].
	current     *xorb
	currentSlot int
	// known locates every chunk this upload stored or found.
	known map[Hash]location
	// found are global deduplication's answers.
	found []foundChunks
	files []pendingFile
}

// xorbSlot is a xorb terms can point into, its hash known once sealed.
type xorbSlot struct {
	hash Hash
	// ours is set for a xorb this upload made, listed in its shards.
	ours  bool
	entry xorbEntry
}

// location is where a chunk is stored: chunk Index of xorbs[Xorb].
type location struct {
	Xorb  int
	Index uint32
}

// foundChunks is one global deduplication answer: chunks, by their hash
// HMAC'd with key (unless it's zero).
type foundChunks struct {
	key    Hash
	chunks map[Hash]location
}

// pendingFile is a file Add chunked, to register in Finish's shards.
type pendingFile struct {
	hash   Hash
	sha256 [32]byte
	terms  []pendingTerm
}

// pendingTerm is a run of a file's chunks in one xorb, which may not be
// sealed yet.
type pendingTerm struct {
	xorb       int
	start, end uint32
	size       uint32
	hashes     []Hash
}

// NewUploader returns an Uploader sending to cas. ctx bounds the whole
// upload.
func NewUploader(ctx context.Context, cas CAS, logger *slog.Logger) *Uploader {
	group, uploadCtx := errgroup.WithContext(ctx)
	group.SetLimit(concurrentXorbUploads)
	uploader := Uploader{
		ctx:        ctx,
		uploadCtx:  uploadCtx,
		cas:        cas,
		logger:     logger,
		group:      group,
		compressor: newCompressor(),
		xorbIndex:  map[Hash]int{},
		known:      map[Hash]location{},
	}
	return &uploader
}

// Added is what Add reports about a file.
type Added struct {
	// Hash is the file's Xet hash.
	Hash Hash
	// Size is the file's length, and NewBytes how much of it was stored:
	// what no xorb held yet, and short runs that did (see minDedupeRun).
	Size, NewBytes int64
}

// minDedupeRun is the fewest stored chunks, in order in one xorb, a file
// reuses rather than storing again, unless they're the whole file: a
// file pieced together from short runs scattered over many xorbs is slow
// to download (see deduplication.md's "Fragmentation Prevention").
const minDedupeRun = 8

// fileUpload is one Add under way.
type fileUpload struct {
	added  Added
	chunks []chunk
	terms  []pendingTerm
	// run holds the chunks just found already stored, in order in one
	// xorb, until it's known whether there are minDedupeRun of them.
	run []foundChunk
}

// foundChunk is a chunk found already stored at where.
type foundChunk struct {
	data  []byte
	hash  Hash
	where location
}

// Add chunks the file reader reads, whose SHA-256 is sha256, storing its
// new chunks. It's registered on the server once Finish succeeds.
func (u *Uploader) Add(reader io.Reader, sha256 [32]byte) (Added, error) {
	chunker := newChunker(reader)
	var file fileUpload
	for {
		data, err := chunker.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Added{}, err
		}
		if u.uploadCtx.Err() != nil {
			return Added{}, u.wait()
		}

		hash := ChunkHash(data)
		where, ok, err := u.locate(hash, len(file.chunks) == 0)
		if err != nil {
			return Added{}, err
		}
		entry := chunk{
			Hash: hash,
			Size: uint64(len(data)),
		}
		file.chunks = append(file.chunks, entry)
		file.added.Size += int64(len(data))

		found := foundChunk{
			data:  data,
			hash:  hash,
			where: where,
		}
		if ok && file.continuesRun(where) {
			found.data = bytes.Clone(data)
			file.run = append(file.run, found)
			continue
		}
		if err := u.settleRun(&file, false); err != nil {
			return Added{}, err
		}
		if ok {
			found.data = bytes.Clone(data)
			file.run = append(file.run, found)
			continue
		}
		if err := u.storeNew(&file, found); err != nil {
			return Added{}, err
		}
	}
	if err := u.settleRun(&file, true); err != nil {
		return Added{}, err
	}

	file.added.Hash = fileHash(file.chunks)
	pending := pendingFile{
		hash:   file.added.Hash,
		sha256: sha256,
		terms:  file.terms,
	}
	u.files = append(u.files, pending)
	return file.added, nil
}

// continuesRun reports whether a chunk stored at where comes right after
// the file's run.
func (f *fileUpload) continuesRun(where location) bool {
	if len(f.run) == 0 {
		return false
	}
	last := f.run[len(f.run)-1].where
	return last.Xorb == where.Xorb && last.Index+1 == where.Index
}

// settleRun ends the file's run: reusing it if it's long enough, or is
// the whole file, which atEnd says could be; else storing it again.
func (u *Uploader) settleRun(file *fileUpload, atEnd bool) error {
	run := file.run
	file.run = nil
	if len(run) >= minDedupeRun || (atEnd && len(file.terms) == 0) {
		for _, found := range run {
			file.terms = extendTerms(file.terms, found.where, found.hash, len(found.data))
		}
		return nil
	}
	for _, found := range run {
		if err := u.storeNew(file, found); err != nil {
			return err
		}
	}
	return nil
}

// storeNew stores a chunk of the file in the current xorb.
func (u *Uploader) storeNew(file *fileUpload, found foundChunk) error {
	where, err := u.store(found.data, found.hash)
	if err != nil {
		return err
	}
	file.added.NewBytes += int64(len(found.data))
	file.terms = extendTerms(file.terms, where, found.hash, len(found.data))
	return nil
}

// locate finds a stored chunk: one this upload stored or found, or, for a
// file's first chunk and some others (see globalDedupeEvery), one global
// deduplication finds.
func (u *Uploader) locate(hash Hash, first bool) (location, bool, error) {
	if where, ok := u.lookup(hash); ok {
		return where, true, nil
	}
	if !first && hash.lastWord()%globalDedupeEvery != 0 {
		return location{}, false, nil
	}
	if err := u.queryGlobal(hash); err != nil {
		return location{}, false, err
	}
	where, ok := u.lookup(hash)
	return where, ok, nil
}

func (u *Uploader) lookup(hash Hash) (location, bool) {
	if where, ok := u.known[hash]; ok {
		return where, true
	}
	for _, found := range u.found {
		key := hash
		if found.key != (Hash{}) {
			key = hash.hmac(found.key)
		}
		if where, ok := found.chunks[key]; ok {
			u.known[hash] = where
			return where, true
		}
	}
	return location{}, false
}

// queryGlobal asks global deduplication about hash, keeping what it
// answers. Deduplication only saves uploading, so an answer that can't be
// read is skipped.
func (u *Uploader) queryGlobal(hash Hash) error {
	answer, err := u.cas.QueryChunk(u.ctx, hash)
	if err != nil {
		if u.ctx.Err() != nil {
			return u.wait()
		}
		u.logger.Warn("global deduplication failed; uploading the chunks it would have found", "chunk", hash.String(), "error", err)
		return nil
	}
	if answer == nil {
		return nil
	}
	parsed, err := parseShard(answer)
	if err != nil {
		u.logger.Warn("global deduplication sent an unreadable answer; uploading the chunks it would have found", "chunk", hash.String(), "error", err)
		return nil
	}

	found := foundChunks{
		key:    parsed.HMACKey,
		chunks: map[Hash]location{},
	}
	for _, entry := range parsed.Xorbs {
		slot, ok := u.xorbIndex[entry.Hash]
		if !ok {
			slot = len(u.xorbs)
			u.xorbs = append(u.xorbs, &xorbSlot{hash: entry.Hash})
			u.xorbIndex[entry.Hash] = slot
		}
		for index, chunk := range entry.Chunks {
			where := location{
				Xorb:  slot,
				Index: uint32(index),
			}
			found.chunks[chunk.Hash] = where
		}
	}
	u.found = append(u.found, found)
	return nil
}

// store compresses a chunk into the current xorb, first sealing it if
// it's full.
func (u *Uploader) store(data []byte, hash Hash) (location, error) {
	stored, scheme, err := u.compressor.compress(data)
	if err != nil {
		return location{}, err
	}
	if u.current == nil || !u.current.fits(len(stored)) {
		u.seal()
		u.current = &xorb{}
		u.currentSlot = len(u.xorbs)
		u.xorbs = append(u.xorbs, &xorbSlot{ours: true})
	}
	where := location{
		Xorb:  u.currentSlot,
		Index: u.current.add(stored, scheme, hash, len(data)),
	}
	u.known[hash] = where
	return where, nil
}

// seal hashes the current xorb and starts uploading it, waiting first if
// concurrentXorbUploads are already under way.
func (u *Uploader) seal() {
	sealed := u.current
	if sealed == nil {
		return
	}
	u.current = nil
	hash := xorbHash(sealed.chunks)
	slot := u.xorbs[u.currentSlot]
	slot.hash = hash
	slot.entry = sealed.entry(hash)
	u.xorbIndex[hash] = u.currentSlot
	u.group.Go(func() error {
		if err := u.cas.UploadXorb(u.uploadCtx, hash, sealed.data); err != nil {
			return fmt.Errorf("upload xorb %s: %w", hash, err)
		}
		return nil
	})
}

// wait waits for the xorb uploads under way, returning the first one's
// error, or why the upload was stopped.
func (u *Uploader) wait() error {
	if err := u.group.Wait(); err != nil {
		return err
	}
	return u.ctx.Err()
}

// extendTerms adds a chunk at where to a file's terms: to its last, if
// the chunk comes right after it in the same xorb, else as a new one.
func extendTerms(terms []pendingTerm, where location, hash Hash, size int) []pendingTerm {
	if count := len(terms); count > 0 {
		last := &terms[count-1]
		if last.xorb == where.Xorb && last.end == where.Index {
			last.end++
			last.size += uint32(size)
			last.hashes = append(last.hashes, hash)
			return terms
		}
	}
	added := pendingTerm{
		xorb:   where.Xorb,
		start:  where.Index,
		end:    where.Index + 1,
		size:   uint32(size),
		hashes: []Hash{hash},
	}
	return append(terms, added)
}

// Finish uploads the last xorb, waits for every xorb upload, then uploads
// shards registering the files Add chunked and listing this upload's
// xorbs.
func (u *Uploader) Finish() error {
	u.seal()
	if err := u.wait(); err != nil {
		return err
	}

	var files []fileEntry
	seen := map[Hash]bool{}
	for _, file := range u.files {
		if seen[file.hash] {
			continue
		}
		seen[file.hash] = true
		entry := fileEntry{
			Hash:   file.hash,
			SHA256: file.sha256,
		}
		for _, pending := range file.terms {
			finished := term{
				Xorb:         u.xorbs[pending.xorb].hash,
				Start:        pending.start,
				End:          pending.end,
				Size:         pending.size,
				Verification: verificationHash(pending.hashes),
			}
			entry.Terms = append(entry.Terms, finished)
		}
		files = append(files, entry)
	}
	var xorbs []xorbEntry
	for _, slot := range u.xorbs {
		if slot.ours {
			xorbs = append(xorbs, slot.entry)
		}
	}

	for _, batch := range shardBatches(files, xorbs) {
		if err := u.cas.UploadShard(u.ctx, marshalShard(batch.files, batch.xorbs)); err != nil {
			return fmt.Errorf("upload shard: %w", err)
		}
	}
	return nil
}

// shardBatch is what one shard holds.
type shardBatch struct {
	files []fileEntry
	xorbs []xorbEntry
}

// shardBatches splits files and xorbs into shards of at most
// maxShardBytes. Every xorb is uploaded by then, so any file can go in
// any shard.
func shardBatches(files []fileEntry, xorbs []xorbEntry) []shardBatch {
	var batches []shardBatch
	var current shardBatch
	size := emptyShardSize
	// makeRoom starts a new shard if current can't take added more bytes.
	makeRoom := func(added int) {
		if size+added > maxShardBytes && (len(current.files) > 0 || len(current.xorbs) > 0) {
			batches = append(batches, current)
			current = shardBatch{}
			size = emptyShardSize
		}
		size += added
	}
	for _, file := range files {
		makeRoom(file.shardSize())
		current.files = append(current.files, file)
	}
	for _, xorb := range xorbs {
		makeRoom(xorb.shardSize())
		current.xorbs = append(current.xorbs, xorb)
	}
	if len(current.files) > 0 || len(current.xorbs) > 0 {
		batches = append(batches, current)
	}
	return batches
}
