package hash

import (
	"crypto"
	"encoding/hex"
)

const (
	MD5     = 11
	SHA1    = 21
	SHA256  = 22
	SHA384  = 23
	SHA512  = 24
	CRC32   = 31
	ADLER32 = 41
)

type Hash interface {
	Type() crypto.Hash
	Hash(data []byte) ([]byte, error)
	HashToString(data []byte) (string, error)
}

func NewHash(format uint64) Hash {
	if format == MD5 {
		return &Md5{}
	} else if format == SHA1 {
		return &Sha1{}
	} else if format == SHA256 {
		return &Sha256{}
	} else if format == SHA384 {
		return &Sha384{}
	} else if format == SHA512 {
		return &Sha512{}
	} else if format == CRC32 {
		return &Crc{}
	} else if format == ADLER32 {
		return &Adler{}
	}

	return nil
}

type hash struct {
}

func (s *hash) ToString(val []byte) string {
	return hex.EncodeToString(val)
}

func (s *hash) ToData(val string) ([]byte, error) {
	return hex.DecodeString(val)
}
