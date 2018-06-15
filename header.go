package abdecrypt

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	Magic string = "ANDROID BACKUP"
)

// AndroidBackupHeader represents Android backup header.
type AndroidBackupHeader struct {
	Version       int
	Compressed    bool
	UserSalt      []byte
	ChecksumSalt  []byte
	Rounds        int
	UserIV        []byte
	MasterKeyBlob []byte
}

// ReadHeader reads Android backup header from reader r.
// Note that ReadHeader returns a reader with remaining data
// to be used to get backup payload. Original reader will be
// advanced by ReadHeader.
func ReadHeader(r io.Reader) (*AndroidBackupHeader, io.Reader, error) {
	ab := &AndroidBackupHeader{}

	br := bufio.NewReader(r)

	for i := 1; i <= 9; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, nil, err
		}
		line = strings.TrimRight(line, "\n")

		switch i {
		case 1:
			if line != Magic {
				return nil, nil, fmt.Errorf("wrong magic: %s", line)
			}
		case 2:
			version, err := strconv.Atoi(line)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid version: %s", line)
			}
			ab.Version = version
		case 3:
			switch line {
			case "0":
				ab.Compressed = false
			case "1":
				ab.Compressed = true
			default:
				return nil, nil, fmt.Errorf("invalid compression info: %s", line)
			}
		case 4:
			switch line {
			case "AES-256":
			default:
				return nil, nil, fmt.Errorf("unsupported encryption algorithm: %s", line)
			}
		case 5:
			userSalt, err := hex.DecodeString(line)
			if err != nil {
				return nil, nil, fmt.Errorf("error parsing user salt: %v", err)
			}
			ab.UserSalt = userSalt
		case 6:
			checksumSalt, err := hex.DecodeString(line)
			if err != nil {
				return nil, nil, fmt.Errorf("error parsing checksum salt: %v", err)
			}
			ab.ChecksumSalt = checksumSalt
		case 7:
			rounds, err := strconv.Atoi(line)
			if err != nil {
				return nil, nil, fmt.Errorf("error parsing rounds: %v", err)
			}
			ab.Rounds = rounds
		case 8:
			userIV, err := hex.DecodeString(line)
			if err != nil {
				return nil, nil, fmt.Errorf("error parsing user IV: %v", err)
			}
			ab.UserIV = userIV
		case 9:
			masterKeyBlob, err := hex.DecodeString(line)
			if err != nil {
				return nil, nil, fmt.Errorf("error parsing master key blob: %v", err)
			}
			ab.MasterKeyBlob = masterKeyBlob
		}
	}
	return ab, br, nil
}
