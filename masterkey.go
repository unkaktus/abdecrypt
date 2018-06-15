package abdecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

// MasterKey represents master key and its parameters.
type MasterKey struct {
	Version int
	IV      []byte
	Key     []byte
}

// extractLV dissects byte stream by one-byte length field.
func extractLV(p []byte) [][]byte {
	ret := make([][]byte, 0)
	for offset := 0; ; {
		if offset >= len(p) {
			break
		}
		l := int(p[offset])
		offset++
		rightOffset := offset + l
		if offset >= len(p) || rightOffset >= len(p) {
			break
		}
		ret = append(ret, p[offset:rightOffset])
		offset = rightOffset
	}
	return ret
}

// DeriveMasterKey derives master key data from backup header and passphrase.
func DeriveMasterKey(ab *AndroidBackupHeader, passphrase string) (*MasterKey, error) {
	switch ab.Version {
	case 5:
		return deriveMasterKeyV5(ab, passphrase)

	}
	return nil, errors.New("unsupported version")
}

func deriveMasterKeyV5(ab *AndroidBackupHeader, passphrase string) (*MasterKey, error) {
	userKey := pbkdf2.Key([]byte(passphrase), ab.UserSalt, ab.Rounds, 32, sha1.New)

	block, err := aes.NewCipher(userKey)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, ab.UserIV)

	decryptedMasterKeyBlob := make([]byte, len(ab.MasterKeyBlob))
	mode.CryptBlocks(decryptedMasterKeyBlob, ab.MasterKeyBlob)

	lvs := extractLV(decryptedMasterKeyBlob)
	if len(lvs) < 3 {
		return nil, errors.New("invalid key blob")
	}
	iv, masterKey, ck := lvs[0], lvs[1], lvs[2]

	ck2 := pbkdf2.Key(convertJavaStringToUTF8(masterKey), ab.ChecksumSalt, ab.Rounds, 32, sha1.New)

	if subtle.ConstantTimeCompare(ck, ck2) != 1 {
		return nil, errors.New("checksum does not match")
	}
	mk := &MasterKey{
		Version: ab.Version,
		IV:      iv,
		Key:     masterKey,
	}
	return mk, nil
}
