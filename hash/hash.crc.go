package hash

import (
	"crypto"
	"hash/crc32"
)

type Crc struct {
	hash
}

func (s *Crc) Type() crypto.Hash {
	return crypto.Hash(0)
}

func (s *Crc) Hash(data []byte) ([]byte, error) {
	h := crc32.NewIEEE()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (s *Crc) HashToString(data []byte) (string, error) {
	hashed, err := s.Hash(data)
	if err != nil {
		return "", err
	}

	return s.ToString(hashed), nil
}
