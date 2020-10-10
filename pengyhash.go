// Package pengyhash implements two variants of the pengyhash hash.
// One variant is the original, non-incremental hash. The other is an
// incremental, 256-bit hash. Both variants are non-cryptographic.
package pengyhash

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

// Size is byte length of a pengyhash256 digest.
const Size = 32

// BlockSize is the internal block size of pengyhash256 in bytes.
const BlockSize = 32

type hash256 struct {
	b     [4]uint64
	s     [4]uint64
	seed  uint64
	total uint64
	tmp   [32]byte
	n     int
}

// New returns a new, seeded hash.Hash computing an incremental variant of
// pengyhash with a 256-bit digest.
func New(seed uint64) hash.Hash {
	var h hash256
	h.seed = seed
	h.s[3] = seed
	return &h
}

func (h *hash256) Size() int {
	return Size
}

func (h *hash256) BlockSize() int {
	return BlockSize
}

func (h *hash256) Reset() {
	h.b[0] = 0
	h.b[1] = 0
	h.b[2] = 0
	h.b[3] = 0
	h.s[0] = 0
	h.s[1] = 0
	h.s[2] = 0
	h.s[3] = h.seed
	h.n = 0
	h.total = 0
}

func (h *hash256) write32(buf []byte) {
	h.b[0] = binary.LittleEndian.Uint64(buf[0:])
	h.b[1] = binary.LittleEndian.Uint64(buf[8:])
	h.b[2] = binary.LittleEndian.Uint64(buf[16:])
	h.b[3] = binary.LittleEndian.Uint64(buf[24:])
	h.s[0] += h.s[1] + h.b[3]
	h.s[1] = h.s[0] + bits.RotateLeft64(h.s[1], 14)
	h.s[2] += h.s[3] + h.b[2]
	h.s[3] = h.s[2] + bits.RotateLeft64(h.s[3], 23)
	h.s[0] += h.s[3] + h.b[1]
	h.s[3] = h.s[0] ^ bits.RotateLeft64(h.s[3], 16)
	h.s[2] += h.s[1] + h.b[0]
	h.s[1] = h.s[2] ^ bits.RotateLeft64(h.s[1], 40)
}

func (h *hash256) Write(buf []byte) (int, error) {
	total := len(buf)
	h.total += uint64(total)

	if h.n != 0 {
		n := copy(h.tmp[h.n:], buf)
		h.n += n
		buf = buf[n:]
		if h.n == 32 {
			h.write32(h.tmp[:])
			h.n = 0
		}
	}

	for ; len(buf) >= 32; buf = buf[32:] {
		h.write32(buf)
	}
	h.n = copy(h.tmp[:], buf[:])

	return total, nil
}

func (h *hash256) Sum(p []byte) []byte {
	var tmp [32]byte
	binary.LittleEndian.PutUint64(tmp[0:], h.b[0])
	binary.LittleEndian.PutUint64(tmp[8:], h.b[1])
	binary.LittleEndian.PutUint64(tmp[16:], h.b[2])
	binary.LittleEndian.PutUint64(tmp[24:], h.b[3])
	copy(tmp[:], h.tmp[:h.n])
	b := [4]uint64{
		binary.LittleEndian.Uint64(tmp[0:]),
		binary.LittleEndian.Uint64(tmp[8:]),
		binary.LittleEndian.Uint64(tmp[16:]),
		binary.LittleEndian.Uint64(tmp[24:]),
	}

	var s [4]uint64
	copy(s[:], h.s[:])
	for i := 0; i < 6; i++ {
		s[0] += s[1] + b[3]
		s[1] = s[0] + bits.RotateLeft64(s[1], 14) + h.total
		s[2] += s[3] + b[2]
		s[3] = s[2] + bits.RotateLeft64(s[3], 23)
		s[0] += s[3] + b[1]
		s[3] = s[0] ^ bits.RotateLeft64(s[3], 16)
		s[2] += s[1] + b[0]
		s[1] = s[2] ^ bits.RotateLeft64(s[1], 40)
	}

	var r [32]byte
	binary.LittleEndian.PutUint64(r[0:], s[0])
	binary.LittleEndian.PutUint64(r[8:], s[1])
	binary.LittleEndian.PutUint64(r[16:], s[2])
	binary.LittleEndian.PutUint64(r[24:], s[3])
	return append(p, r[:]...)
}

// Pengyhash computes the original, non-incremental hash.
func Pengyhash(buf []byte, seed uint32) uint64 {
	b := [4]uint64{}
	s := [4]uint64{0, 0, 0, uint64(len(buf))}

	for ; len(buf) >= 32; buf = buf[32:] {
		b[0] = binary.LittleEndian.Uint64(buf[0:])
		b[1] = binary.LittleEndian.Uint64(buf[8:])
		b[2] = binary.LittleEndian.Uint64(buf[16:])
		b[3] = binary.LittleEndian.Uint64(buf[24:])
		s[0] += s[1] + b[3]
		s[1] = s[0] + bits.RotateLeft64(s[1], 14)
		s[2] += s[3] + b[2]
		s[3] = s[2] + bits.RotateLeft64(s[3], 23)
		s[0] += s[3] + b[1]
		s[3] = s[0] ^ bits.RotateLeft64(s[3], 16)
		s[2] += s[1] + b[0]
		s[1] = s[2] ^ bits.RotateLeft64(s[1], 40)
	}

	var tmp [32]byte
	binary.LittleEndian.PutUint64(tmp[0:], b[0])
	binary.LittleEndian.PutUint64(tmp[8:], b[1])
	binary.LittleEndian.PutUint64(tmp[16:], b[2])
	binary.LittleEndian.PutUint64(tmp[24:], b[3])
	copy(tmp[:], buf[:])
	b[0] = binary.LittleEndian.Uint64(tmp[0:])
	b[1] = binary.LittleEndian.Uint64(tmp[8:])
	b[2] = binary.LittleEndian.Uint64(tmp[16:])
	b[3] = binary.LittleEndian.Uint64(tmp[24:])

	for i := 0; i < 6; i++ {
		s[0] += s[1] + b[3]
		s[1] = s[0] + bits.RotateLeft64(s[1], 14) + uint64(seed)
		s[2] += s[3] + b[2]
		s[3] = s[2] + bits.RotateLeft64(s[3], 23)
		s[0] += s[3] + b[1]
		s[3] = s[0] ^ bits.RotateLeft64(s[3], 16)
		s[2] += s[1] + b[0]
		s[1] = s[2] ^ bits.RotateLeft64(s[1], 40)
	}

	return s[0] + s[1] + s[2] + s[3]
}
