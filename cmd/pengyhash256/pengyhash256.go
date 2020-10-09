package main

import (
	"flag"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/skeeto/pengyhash"
)

func run(h hash.Hash, filename string) error {
	var r io.Reader
	if filename == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(filename)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}

	_, err := io.Copy(h, r)
	if err != nil {
		return err
	}
	fmt.Printf("%02x  %s\n", h.Sum(nil), filename)

	return nil
}

func main() {
	seed := flag.Uint64("seed", 1, "hash function seed")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		args = []string{"-"}
	}

	for _, filename := range args {
		err := run(pengyhash.New(*seed), filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pengyhash256: %s\n", err)
			os.Exit(1)
		}
	}

}
