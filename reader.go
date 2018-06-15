package abdecrypt

import (
	"io"
)

// NewReader creates an extractor that decrypts and decompresses
// Android backup using the passphrase.
func NewReader(r io.Reader, passphrase string) (io.Reader, error) {
	abheader, blobReader, err := ReadHeader(r)
	if err != nil {
		return nil, err
	}
	mk, err := DeriveMasterKey(abheader, passphrase)
	if err != nil {
		return nil, err
	}

	decryptedReader, err := Decrypt(blobReader, mk)
	if err != nil {
		return nil, err
	}

	decompressedReader, err := Decompress(decryptedReader, abheader)
	if err != nil {
		return nil, err
	}
	return decompressedReader, nil

}
