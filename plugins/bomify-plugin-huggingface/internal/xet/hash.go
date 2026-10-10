// Package xet uploads files with the Xet protocol, the Hugging Face Hub's
// storage, as https://huggingface.co/docs/xet specifies it (version
// 1.1.0): content-defined chunks, deduplicated within an upload and
// against the whole Hub, packed into xorbs and registered with shards.
package xet

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"

	"lukechampine.com/blake3"
)

// Hash is a 32-byte Xet hash: of a chunk, a xorb, or a file.
type Hash [32]byte

// Keys for the BLAKE3 keyed hashes, from hashing.md.
var (
	dataKey = Hash{
		102, 151, 245, 119, 91, 149, 80, 222, 49, 53, 203, 172, 165, 151, 24, 28,
		157, 228, 33, 16, 155, 235, 43, 88, 180, 208, 176, 75, 147, 173, 242, 41,
	}
	internalNodeKey = Hash{
		1, 126, 197, 199, 165, 71, 41, 150, 253, 148, 102, 102, 180, 138, 2, 230,
		93, 221, 83, 111, 55, 199, 109, 210, 248, 99, 82, 230, 74, 83, 113, 63,
	}
	verificationKey = Hash{
		127, 24, 87, 214, 206, 86, 237, 102, 18, 127, 249, 19, 231, 165, 195, 243,
		164, 205, 38, 213, 181, 219, 73, 230, 65, 36, 152, 127, 40, 251, 148, 195,
	}
)

// String is h as the protocol writes it in URLs and listings: each 8-byte
// word as a little-endian integer, in hex (see api.md), not h's bytes in
// order.
func (h Hash) String() string {
	reordered := swapWords(h)
	return hex.EncodeToString(reordered[:])
}

// ParseHash parses a hash written as String writes it.
func ParseHash(text string) (Hash, error) {
	reordered, err := hex.DecodeString(text)
	if err != nil || len(reordered) != len(Hash{}) {
		return Hash{}, fmt.Errorf("%q isn't a 64-digit hex Xet hash", text)
	}
	return swapWords(Hash(reordered)), nil
}

// swapWords reverses the bytes of each of h's 8-byte words, which turns
// a hash's bytes into the order String writes them in, and back.
func swapWords(h Hash) Hash {
	var swapped Hash
	for word := 0; word < 4; word++ {
		for index := 0; index < 8; index++ {
			swapped[word*8+index] = h[word*8+7-index]
		}
	}
	return swapped
}

// lastWord is h's last 8 bytes as a little-endian integer, which decides
// both where the hash tree cuts and which chunks global deduplication
// covers.
func (h Hash) lastWord() uint64 {
	return binary.LittleEndian.Uint64(h[24:])
}

func keyedHash(key Hash, data []byte) Hash {
	hasher := blake3.New(32, key[:])
	hasher.Write(data)
	var h Hash
	hasher.Sum(h[:0])
	return h
}

// ChunkHash is a chunk's hash.
func ChunkHash(data []byte) Hash {
	return keyedHash(dataKey, data)
}

// hmac is h keyed by key, as global deduplication hides chunk hashes.
func (h Hash) hmac(key Hash) Hash {
	return keyedHash(key, h[:])
}

// chunk is a chunk's hash and length, all the hash tree needs of it.
type chunk struct {
	Hash Hash
	Size uint64
}

// Branching of the hash tree, from xet-core's aggregated_hashes.rs, which
// hashing.md leaves out: a node's children end at the first one, from the
// third on, whose hash is a multiple of meanBranching, or at the
// maxBranching'th.
const (
	meanBranching = 4
	maxBranching  = 2*meanBranching + 1
)

// treeHash is the root of the hash tree over chunks: xet-core's
// aggregated_node_hash. Each level groups its nodes (see meanBranching)
// and hashes each group into one node of the next, until one is left.
func treeHash(chunks []chunk) Hash {
	if len(chunks) == 0 {
		return Hash{}
	}
	level := chunks
	for len(level) > 1 {
		var next []chunk
		for len(level) > 0 {
			size := groupSize(level)
			next = append(next, mergeNodes(level[:size]))
			level = level[size:]
		}
		level = next
	}
	return level[0].Hash
}

// groupSize is how many of nodes the next node of the tree's next level
// covers.
func groupSize(nodes []chunk) int {
	if len(nodes) <= 2 {
		return len(nodes)
	}
	end := min(maxBranching, len(nodes))
	for index := 2; index < end; index++ {
		if nodes[index].Hash.lastWord()%meanBranching == 0 {
			return index + 1
		}
	}
	return end
}

// mergeNodes hashes nodes into their parent: a line "<hash> : <size>\n"
// for each, keyed with internalNodeKey.
func mergeNodes(nodes []chunk) chunk {
	var buffer []byte
	var total uint64
	for _, node := range nodes {
		buffer = append(buffer, node.Hash.String()...)
		buffer = append(buffer, " : "...)
		buffer = strconv.AppendUint(buffer, node.Size, 10)
		buffer = append(buffer, '\n')
		total += node.Size
	}
	merged := chunk{
		Hash: keyedHash(internalNodeKey, buffer),
		Size: total,
	}
	return merged
}

// xorbHash is the hash of a xorb holding chunks.
func xorbHash(chunks []chunk) Hash {
	return treeHash(chunks)
}

// fileHash is the hash of a file made of chunks, its Xet file ID.
func fileHash(chunks []chunk) Hash {
	if len(chunks) == 0 {
		return Hash{}
	}
	return treeHash(chunks).hmac(Hash{})
}

// verificationHash proves the uploader holds the chunks a file's term
// covers: their hashes, concatenated, keyed with verificationKey.
func verificationHash(hashes []Hash) Hash {
	buffer := make([]byte, 0, len(hashes)*len(Hash{}))
	for _, h := range hashes {
		buffer = append(buffer, h[:]...)
	}
	return keyedHash(verificationKey, buffer)
}
