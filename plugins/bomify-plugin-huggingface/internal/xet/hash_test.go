package xet

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Hashes the reference files record for their CSV file (see
// testdata/README.md).
const (
	referenceXorbHash  = "eea25d6ee393ccae385820daed127b96ef0ea034dfb7cf6da3a950ce334b7632"
	referenceFileHash  = "118a53328412787fee04011dcf82fdc4acf3a4a1eddec341c910d30a306aaf97"
	referenceRangeHash = "d81c11b1fc9bc2a25587108c675bbfe65ca2e5d350b0cd92c58329fcc8444178"
)

// referenceChunks reads testdata/reference.chunks, the CSV file's chunks.
func referenceChunks(t *testing.T) []chunk {
	t.Helper()
	opened, err := os.Open(filepath.Join("testdata", "reference.chunks"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	var chunks []chunk
	scanner := bufio.NewScanner(opened)
	for scanner.Scan() {
		hashText, sizeText, ok := strings.Cut(strings.TrimSpace(scanner.Text()), " ")
		if !ok {
			continue
		}
		hash, err := ParseHash(hashText)
		if err != nil {
			t.Fatal(err)
		}
		size, err := strconv.ParseUint(sizeText, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, chunk{Hash: hash, Size: size})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 796 {
		t.Fatalf("read %d reference chunks, want 796", len(chunks))
	}
	return chunks
}

func chunkHashes(chunks []chunk) []Hash {
	hashes := make([]Hash, 0, len(chunks))
	for _, chunk := range chunks {
		hashes = append(hashes, chunk.Hash)
	}
	return hashes
}

func TestHashString(t *testing.T) {
	var h Hash
	for index := range h {
		h[index] = byte(index)
	}
	// api.md's example, whose last word it misprints.
	want := "0706050403020100" + "0f0e0d0c0b0a0908" + "1716151413121110" + "1f1e1d1c1b1a1918"
	if got := h.String(); got != want {
		t.Errorf("String = %s, want %s", got, want)
	}
	if parsed, err := ParseHash(want); err != nil || parsed != h {
		t.Errorf("ParseHash(%s) = %v, %v; want %v", want, parsed, err, h)
	}
	for _, text := range []string{"", "00", strings.Repeat("g", 64), strings.Repeat("0", 66)} {
		if _, err := ParseHash(text); err == nil {
			t.Errorf("ParseHash(%q) succeeded", text)
		}
	}
}

func TestChunkHash(t *testing.T) {
	name := "099cb228194fe640e36a6c7d274ee5ed3a714ccd557a0951d9b6b43a7292b5d1"
	data, err := os.ReadFile(filepath.Join("testdata", name+".chunk"))
	if err != nil {
		t.Fatal(err)
	}
	if got := ChunkHash(data).String(); got != name {
		t.Errorf("ChunkHash = %s, want %s", got, name)
	}
}

func TestReferenceHashes(t *testing.T) {
	chunks := referenceChunks(t)
	if got := xorbHash(chunks).String(); got != referenceXorbHash {
		t.Errorf("xorbHash = %s, want %s", got, referenceXorbHash)
	}
	if got := fileHash(chunks).String(); got != referenceFileHash {
		t.Errorf("fileHash = %s, want %s", got, referenceFileHash)
	}
	if got := verificationHash(chunkHashes(chunks)).String(); got != referenceRangeHash {
		t.Errorf("verificationHash = %s, want %s", got, referenceRangeHash)
	}
}

func TestTreeHashSmall(t *testing.T) {
	if got := treeHash(nil); got != (Hash{}) {
		t.Errorf("treeHash(none) = %s, want zero", got)
	}
	one := chunk{Hash: ChunkHash([]byte("one")), Size: 3}
	if got, want := treeHash([]chunk{one}), one.Hash; got != want {
		t.Errorf("treeHash(one chunk) = %s, want the chunk's hash %s", got, want)
	}
}
