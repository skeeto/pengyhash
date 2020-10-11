// Package pengyhash implements two variants of the pengyhash hash.
// One variant is the original, non-incremental hash. The other is an
// incremental, 256-bit hash. Both variants are non-cryptographic.
package pengyhash

import (
	"encoding/binary"
	"errors"
	"hash"
	"math/bits"
)

// Size is byte length of a pengyhash256 digest.
const Size = 32

// BlockSize is the internal block size of pengyhash256 in bytes.
const BlockSize = 32

type hash256 struct {
	block [32]byte
	s     [4]uint64
	seed  uint64
	total uint64
	n     int
}

// New returns a new, seeded hash.Hash computing an incremental variant of
// pengyhash with a 256-bit digest. Also implements encoding.BinaryMarshaler
// and encoding.BinaryUnmarshaler to marshal and unmarshal the internal state
// of the hash.
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
	*h = hash256{}
	h.s[3] = h.seed
}

func (h *hash256) write32(buf []byte) {
	b := [4]uint64{
		binary.LittleEndian.Uint64(buf[0:]),
		binary.LittleEndian.Uint64(buf[8:]),
		binary.LittleEndian.Uint64(buf[16:]),
		binary.LittleEndian.Uint64(buf[24:]),
	}
	h.s[0] += h.s[1] + b[3]
	h.s[1] = h.s[0] + bits.RotateLeft64(h.s[1], 14)
	h.s[2] += h.s[3] + b[2]
	h.s[3] = h.s[2] + bits.RotateLeft64(h.s[3], 23)
	h.s[0] += h.s[3] + b[1]
	h.s[3] = h.s[0] ^ bits.RotateLeft64(h.s[3], 16)
	h.s[2] += h.s[1] + b[0]
	h.s[1] = h.s[2] ^ bits.RotateLeft64(h.s[1], 40)
}

func (h *hash256) Write(buf []byte) (int, error) {
	total := len(buf)
	h.total += uint64(total)

	if h.n != 0 {
		n := copy(h.block[h.n:], buf)
		h.n += n
		buf = buf[n:]
		if h.n == 32 {
			h.write32(h.block[:])
			h.n = 0
		}
	}

	for ; len(buf) >= 32; buf = buf[32:] {
		h.write32(buf)
		if len(buf) < 64 {
			copy(h.block[:], buf[:])
		}
	}
	h.n = copy(h.block[:], buf[:])

	return total, nil
}

func (h *hash256) Sum(p []byte) []byte {
	b := [4]uint64{
		binary.LittleEndian.Uint64(h.block[0:]),
		binary.LittleEndian.Uint64(h.block[8:]),
		binary.LittleEndian.Uint64(h.block[16:]),
		binary.LittleEndian.Uint64(h.block[24:]),
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

func (h *hash256) MarshalBinary() ([]byte, error) {
	var buf [32 + 32 + 8 + 8 + 1]byte
	copy(buf[0:], h.block[:])
	binary.LittleEndian.PutUint64(buf[32:], h.s[0])
	binary.LittleEndian.PutUint64(buf[40:], h.s[1])
	binary.LittleEndian.PutUint64(buf[48:], h.s[2])
	binary.LittleEndian.PutUint64(buf[56:], h.s[3])
	binary.LittleEndian.PutUint64(buf[64:], h.seed)
	binary.LittleEndian.PutUint64(buf[72:], h.total)
	buf[80] = byte(h.n)
	return buf[:], nil
}

func (h *hash256) UnmarshalBinary(data []byte) error {
	if len(data) < 32+32+8+8+1 {
		return errors.New("invalid length")
	}
	if data[80] >= 32 {
		return errors.New("invalid data")
	}

	copy(h.block[:], data[0:])
	h.s[0] = binary.LittleEndian.Uint64(data[32:])
	h.s[1] = binary.LittleEndian.Uint64(data[40:])
	h.s[2] = binary.LittleEndian.Uint64(data[48:])
	h.s[3] = binary.LittleEndian.Uint64(data[56:])
	h.seed = binary.LittleEndian.Uint64(data[64:])
	h.total = binary.LittleEndian.Uint64(data[72:])
	h.n = int(data[80])

	return nil
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
