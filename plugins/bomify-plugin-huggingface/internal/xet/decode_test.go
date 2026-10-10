package xet

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/pierrec/lz4/v4"
)

// The inverse of storing chunks in xorbs, which only the tests need: the
// plugin never downloads through Xet.

// decompress returns a chunk stored with scheme, which must come to size
// bytes.
func decompress(scheme byte, stored []byte, size int) ([]byte, error) {
	var data []byte
	switch scheme {
	case compressionNone:
		data = stored
	case compressionLZ4, compressionBG4LZ4:
		data = make([]byte, 0, size)
		buffer := bytes.NewBuffer(data)
		// One byte more than size, to tell a chunk that's too long.
		if _, err := io.Copy(buffer, io.LimitReader(lz4.NewReader(bytes.NewReader(stored)), int64(size)+1)); err != nil {
			return nil, fmt.Errorf("decompress chunk: %w", err)
		}
		data = buffer.Bytes()
		if scheme == compressionBG4LZ4 {
			data = byteUngroup(data)
		}
	default:
		return nil, fmt.Errorf("unknown chunk compression scheme %d", scheme)
	}
	if len(data) != size {
		return nil, fmt.Errorf("chunk is %d bytes, but its header says %d", len(data), size)
	}
	return data, nil
}

// decodeChunks decompresses count chunks from data, a run of a xorb's
// serialized chunks, which they must fill exactly.
func decodeChunks(data []byte, count int) ([][]byte, error) {
	chunks := make([][]byte, 0, count)
	for range count {
		if len(data) < chunkHeaderSize {
			return nil, errors.New("xorb data ends early")
		}
		if data[0] != 0 {
			return nil, fmt.Errorf("chunk header version %d, not 0", data[0])
		}
		storedSize := int(data[1]) | int(data[2])<<8 | int(data[3])<<16
		size := int(data[5]) | int(data[6])<<8 | int(data[7])<<16
		if len(data) < chunkHeaderSize+storedSize || size > maxChunkSize {
			return nil, errors.New("xorb chunk is larger than the data or the maximum")
		}
		chunk, err := decompress(data[4], data[chunkHeaderSize:chunkHeaderSize+storedSize], size)
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, chunk)
		data = data[chunkHeaderSize+storedSize:]
	}
	if len(data) != 0 {
		return nil, fmt.Errorf("xorb data has %d bytes after its %d chunks", len(data), count)
	}
	return chunks, nil
}

// byteUngroup undoes byteGroup. Group g holds len/4 bytes, plus one if g
// is under len%4.
func byteUngroup(grouped []byte) []byte {
	data := make([]byte, len(grouped))
	start := 0
	for group := range 4 {
		size := len(grouped) / 4
		if group < len(grouped)%4 {
			size++
		}
		for offset, value := range grouped[start : start+size] {
			data[group+4*offset] = value
		}
		start += size
	}
	return data
}

// decodeXorb decompresses every chunk of a serialized xorb.
func decodeXorb(data []byte) ([][]byte, error) {
	var chunks [][]byte
	for len(data) > 0 {
		if len(data) < chunkHeaderSize {
			return nil, errors.New("xorb data ends early")
		}
		storedSize := int(data[1]) | int(data[2])<<8 | int(data[3])<<16
		end := chunkHeaderSize + storedSize
		if len(data) < end {
			return nil, errors.New("xorb data ends early")
		}
		chunk, err := decodeChunks(data[:end], 1)
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, chunk[0])
		data = data[end:]
	}
	return chunks, nil
}
