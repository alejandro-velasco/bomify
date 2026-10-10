package xet

import (
	"bytes"

	"github.com/pierrec/lz4/v4"
)

// Chunk compression schemes (see xorb.md). LZ4 is the standard LZ4 frame
// format, as xet-core writes it.
const (
	compressionNone = 0
	compressionLZ4  = 1
	// compressionBG4LZ4 is LZ4 of the chunk's bytes grouped by their
	// position in each 4 (see byteGroup), which compresses arrays of
	// numbers, like model weights, much better.
	compressionBG4LZ4 = 2
)

// compressor compresses chunks, reusing its buffers.
type compressor struct {
	writer         *lz4.Writer
	plain, grouped bytes.Buffer
}

func newCompressor() *compressor {
	// Frames as xet-core's lz4_flex writes them: 64 KiB blocks and no
	// checksums, which the chunk and xorb hashes make redundant.
	writer := lz4.NewWriter(nil)
	writer.Apply(lz4.BlockSizeOption(lz4.Block64Kb), lz4.ChecksumOption(false))
	compressor := compressor{writer: writer}
	return &compressor
}

// compress returns data as stored in a xorb, and the scheme it's stored
// with: whichever of LZ4 and byte-grouped LZ4 is smaller, or data itself
// if neither is smaller than it. The result is valid until the next call.
func (c *compressor) compress(data []byte) ([]byte, byte, error) {
	if err := c.frame(&c.plain, data); err != nil {
		return nil, 0, err
	}
	if err := c.frame(&c.grouped, byteGroup(data)); err != nil {
		return nil, 0, err
	}
	switch {
	case c.grouped.Len() < c.plain.Len() && c.grouped.Len() < len(data):
		return c.grouped.Bytes(), compressionBG4LZ4, nil
	case c.plain.Len() < len(data):
		return c.plain.Bytes(), compressionLZ4, nil
	default:
		return data, compressionNone, nil
	}
}

// frame writes data to buffer as one LZ4 frame.
func (c *compressor) frame(buffer *bytes.Buffer, data []byte) error {
	buffer.Reset()
	c.writer.Reset(buffer)
	if _, err := c.writer.Write(data); err != nil {
		return err
	}
	return c.writer.Close()
}

// byteGroup groups data's bytes by their position in each 4: first every
// 4th byte from the first, then from the second, and so on (see
// xorb.md).
func byteGroup(data []byte) []byte {
	grouped := make([]byte, 0, len(data))
	for group := range 4 {
		for index := group; index < len(data); index += 4 {
			grouped = append(grouped, data[index])
		}
	}
	return grouped
}
