package pengyhash

import (
	"bytes"
	"encoding"
	"testing"
)

func TestOutput(t *testing.T) {
	// from reference implementation
	const want64 = 0xf4f178b8b8deb902
	var input [39]byte
	// from reference implementation (internal state)
	var want = [...]byte{
		0x01, 0x54, 0xba, 0x8a, 0x00, 0x37, 0x34, 0x6c,
		0x32, 0x6a, 0xde, 0x13, 0x9f, 0xda, 0xd7, 0x4b,
		0xd0, 0x16, 0x99, 0x27, 0xbc, 0x2a, 0x26, 0x8c,
		0xff, 0xe3, 0xac, 0xf2, 0x5c, 0x3c, 0xbf, 0xb0,
	}

	got64 := Pengyhash(input[:], uint32(len(input)))
	if got64 != want64 {
		t.Errorf("Pengyhash([%d]byte{}[:], %d), got %016x, want %016x",
			len(input), len(input), got64, uint64(want64))
	}

	h := New(uint64(len(input)))
	h.Write(input[:])
	got := h.Sum(nil)
	if !bytes.Equal(want[:], got) {
		t.Errorf("Sum(), got %#v, want %#v", got, want)
	}
}

func TestMarshal(t *testing.T) {
	var zero [1<<20 + 31]byte
	h0 := New(1)
	h0.Write(zero[:])
	buf, _ := h0.(encoding.BinaryMarshaler).MarshalBinary()
	want := h0.Sum(nil)

	h1 := New(0)
	h1.(encoding.BinaryUnmarshaler).UnmarshalBinary(buf)
	got := h1.Sum(nil)

	if !bytes.Equal(want, got) {
		t.Errorf("Marshaler got %#v, want %#v", got, want)
	}
}
