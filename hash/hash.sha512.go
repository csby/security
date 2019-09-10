package hash

import (
	"crypto"
	"crypto/sha512"
)

type Sha512 struct {
	hash
}

func (s *Sha512) Type() crypto.Hash {
	return crypto.SHA512
}

func (s *Sha512) Hash(data []byte) ([]byte, error) {
	h := sha512.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (s *Sha512) HashToString(data []byte) (string, error) {
	hashed, err := s.Hash(data)
	if err != nil {
		return "", err
	}

	return s.ToString(hashed), nil
}
