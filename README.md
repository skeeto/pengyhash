# pengyhash (Go implementation)

This is a Go implementation of [pengyhash][ph]. It implements the
original, non-incremental hash function as well as an incremental
(`hash.Hash`), 256-bit variant, pengyhash256. The 256-bit variant swaps
the usage of size and seed — i.e. size is no longer needed during
initialization — and accepts a 64-bit seed.

See also: [API documentation][doc]


[doc]: https://pkg.go.dev/github.com/skeeto/pengyhash
[ph]: https://github.com/tinypeng/pengyhash
