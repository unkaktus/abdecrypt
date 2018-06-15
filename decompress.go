package abdecrypt

import (
	"compress/zlib"
	"errors"
	"io"
)

// Decompress decompresses payload r of an Android backup
// consulting abheader.
func Decompress(r io.Reader, abheader *AndroidBackupHeader) (io.Reader, error) {
	if !abheader.Compressed {
		return r, nil
	}
	switch abheader.Version {
	case 5:
		return decompressV5(r)

	}
	return nil, errors.New("unsupported version")
}

func decompressV5(r io.Reader) (io.Reader, error) {
	return zlib.NewReader(r)
}
