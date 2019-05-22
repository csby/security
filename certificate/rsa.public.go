package certificate

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/csby/security/encoding"
	"github.com/csby/security/hash"
	"os"
)

type RSAPublic struct {
	key *rsa.PublicKey
}

func (s *RSAPublic) Key() *rsa.PublicKey {
	return s.key
}

func (s *RSAPublic) Length() int {
	if s.key == nil {
		return 0
	}

	return s.key.N.BitLen()
}

func (s *RSAPublic) Base64() string {
	data, err := x509.MarshalPKIXPublicKey(s.key)
	if err != nil {
		return ""
	}

	return encoding.ToBase64String(data)
}

func (s *RSAPublic) Encrypt(data []byte) ([]byte, error) {
	if s.key == nil {
		return nil, fmt.Errorf("invalid key")
	}

	var buf bytes.Buffer
	maxSize := s.key.N.BitLen()/8 - 11
	dataLength := len(data)
	count := dataLength / maxSize
	offset := 0
	for index := 1; index <= count; index++ {
		vav, err := rsa.EncryptPKCS1v15(rand.Reader, s.key, data[offset:offset+maxSize])
		if err != nil {
			return nil, err
		}

		_, err = buf.Write(vav)
		if err != nil {
			return nil, err
		}

		offset += maxSize
	}

	if dataLength > offset {
		vav, err := rsa.EncryptPKCS1v15(rand.Reader, s.key, data[offset:dataLength])
		if err != nil {
			return nil, err
		}

		_, err = buf.Write(vav)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func (s *RSAPublic) Verify(data []byte, signature []byte, h hash.Hash) error {
	if h == nil {
		h = &hash.Md5{}
	}
	hashed, err := h.Hash(data)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(s.key, h.Type(), hashed, signature)
}

func (s *RSAPublic) FromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	fileSize := fileInfo.Size()
	if fileSize <= 0 {
		return fmt.Errorf("invalid file")
	}

	buf := make([]byte, fileSize)
	num, err := file.Read(buf)
	if err != nil {
		return err
	} else if num <= 0 {
		return fmt.Errorf("read file fail")
	}

	block, _ := pem.Decode(buf)
	if block == nil {
		return fmt.Errorf("invalid file")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid file")
	}
	s.key = publicKey

	return nil
}

func (s *RSAPublic) ToMemory() ([]byte, error) {
	if s.key == nil {
		return nil, fmt.Errorf("invalid key")
	}

	data, err := x509.MarshalPKIXPublicKey(s.key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	}

	return pem.EncodeToMemory(block), nil

}
