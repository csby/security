package hash

import (
	"crypto"
	"crypto/sha512"
)

type Sha384 struct {
	hash
}

func (s *Sha384) Type() crypto.Hash {
	return crypto.SHA384
}

func (s *Sha384) Hash(data []byte) ([]byte, error) {
	h := sha512.New384()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (s *Sha384) HashToString(data []byte) (string, error) {
	hashed, err := s.Hash(data)
	if err != nil {
		return "", err
	}

	return s.ToString(hashed), nil
}
