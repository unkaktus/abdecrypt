package main

import (
	"flag"
	"io"
	"log"
	"os"

	"github.com/nogoegst/abdecrypt"
)

func main() {
	log.SetFlags(0)
	var passphrase = flag.String("p", "", "passphrase")
	flag.Parse()

	if *passphrase == "" {
		log.Fatal("empty passphrase")
	}

	if len(flag.Args()) != 1 {
		log.Fatal("no file specified")
	}
	w := os.Stdout
	var f io.ReadCloser
	var err error
	filename := flag.Args()[0]
	if filename == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(filename)
		if err != nil {
			log.Fatal(err)
		}
	}

	r, err := abdecrypt.NewReader(f, *passphrase)
	if err != nil {
		log.Fatal(err)
	}

	_, err = io.Copy(w, r)
	if err != nil {
		log.Fatal(err)
	}
}
