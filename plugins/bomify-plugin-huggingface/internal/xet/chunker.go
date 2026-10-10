package xet

import (
	"errors"
	"io"
)

// Chunk boundaries, from chunking.md: a chunk ends after a byte at which
// the rolling hash has chunkMask's bits all zero, about every 64 KiB, but
// is never shorter than minChunkSize, except a file's last, or longer
// than maxChunkSize.
const (
	minChunkSize = 8 << 10
	maxChunkSize = 128 << 10
	chunkMask    = 0xffff000000000000
)

// chunker splits a stream into content-defined chunks.
type chunker struct {
	reader io.Reader
	// buffer holds what's been read; buffer[start:end] isn't chunked yet.
	buffer     []byte
	start, end int
	eof        bool
}

func newChunker(reader io.Reader) *chunker {
	chunker := chunker{
		reader: reader,
		buffer: make([]byte, 4*maxChunkSize),
	}
	return &chunker
}

// next returns the next chunk, valid until the next call, or io.EOF after
// the last.
func (c *chunker) next() ([]byte, error) {
	if err := c.fill(); err != nil {
		return nil, err
	}
	data := c.buffer[c.start:c.end]
	if len(data) == 0 {
		return nil, io.EOF
	}
	size := cut(data)
	c.start += size
	return data[:size], nil
}

// fill reads until a whole chunk is buffered (maxChunkSize bytes), or the
// stream ends.
func (c *chunker) fill() error {
	if c.end-c.start >= maxChunkSize || c.eof {
		return nil
	}
	copy(c.buffer, c.buffer[c.start:c.end])
	c.end -= c.start
	c.start = 0
	for c.end < maxChunkSize && !c.eof {
		read, err := c.reader.Read(c.buffer[c.end:])
		c.end += read
		if errors.Is(err, io.EOF) {
			c.eof = true
		} else if err != nil {
			return err
		}
	}
	return nil
}

// cut returns how long the chunk data starts with is: through the first
// boundary, or all of data, up to maxChunkSize, if it has none.
func cut(data []byte) int {
	var rolling uint64
	limit := min(len(data), maxChunkSize)
	for index := 0; index < limit; index++ {
		rolling = rolling<<1 + gearTable[data[index]]
		if index+1 >= minChunkSize && rolling&chunkMask == 0 {
			return index + 1
		}
	}
	return limit
}
