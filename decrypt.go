package abdecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

// Decrypt decrypts payload of an Android backup using master key mk.
func Decrypt(r io.Reader, mk *MasterKey) (io.Reader, error) {
	switch mk.Version {
	case 5:
		return decryptV5(r, mk.IV, mk.Key)
	}
	return nil, errors.New("unsupported version")
}

func decryptV5(r io.Reader, iv, key []byte) (io.Reader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	buf := make([]byte, mode.BlockSize())
	dr, dw := io.Pipe()
	go func() {
		for {
			_, err := io.ReadFull(r, buf)
			if err != nil {
				dw.CloseWithError(err)
				return

			}
			mode.CryptBlocks(buf, buf)
			_, err = dw.Write(buf)
			if err != nil {
				return
			}
		}
	}()
	return dr, nil
}
