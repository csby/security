package certificate

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/csby/security/hash"
	"io/ioutil"
	"os"
	"path/filepath"
)

type RSAPrivate struct {
	key *rsa.PrivateKey
}

func (s *RSAPrivate) Key() *rsa.PrivateKey {
	return s.key
}

func (s *RSAPrivate) Length() int {
	if s.key == nil {
		return 0
	}

	return s.key.N.BitLen()
}

func (s *RSAPrivate) Public() (*RSAPublic, error) {
	if s.key == nil {
		return nil, fmt.Errorf("invalid private key")
	}

	data, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	if err != err {
		return nil, err
	}
	key, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}

	return &RSAPublic{
		key: key.(*rsa.PublicKey),
	}, nil
}

func (s *RSAPrivate) Decrypt(data []byte) ([]byte, error) {
	if s.key == nil {
		return nil, fmt.Errorf("invalid key")
	}

	var buf bytes.Buffer
	maxSize := s.key.N.BitLen() / 8
	dataLength := len(data)
	count := dataLength / maxSize
	offset := 0
	for index := 1; index <= count; index++ {
		vav, err := rsa.DecryptPKCS1v15(rand.Reader, s.key, data[offset:offset+maxSize])
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
		vav, err := rsa.DecryptPKCS1v15(rand.Reader, s.key, data[offset:dataLength])
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

func (s *RSAPrivate) Sign(data []byte, h hash.Hash) ([]byte, error) {
	if h == nil {
		h = &hash.Md5{}
	}
	hashed, err := h.Hash(data)
	if err != nil {
		return nil, err
	}

	return rsa.SignPKCS1v15(rand.Reader, s.key, h.Type(), hashed)
}

func (s *RSAPrivate) Create(length int) error {
	key, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		return err
	}
	s.key = key

	return nil
}

func (s *RSAPrivate) ToMemory(password string) ([]byte, error) {
	block, err := s.encode(password)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(block), nil
}

func (s *RSAPrivate) ToFile(path, password string) error {
	block, err := s.encode(password)
	if err != nil {
		return err
	}

	folder := filepath.Dir(path)
	err = os.MkdirAll(folder, 0777)
	if err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, block)
}

func (s *RSAPrivate) FromFile(path, password string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("invalid private key file")
	}

	blockData := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		blockData, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != err {
			return fmt.Errorf("password invalid: %v", err)
		}
	}

	key, err := x509.ParsePKCS1PrivateKey(blockData)
	if err != nil {
		return err
	}
	s.key = key

	return nil
}

func (s *RSAPrivate) encode(password string) (block *pem.Block, err error) {
	if len(password) > 0 {
		block, err = x509.EncryptPEMBlock(rand.Reader,
			"RSA PRIVATE KEY",
			x509.MarshalPKCS1PrivateKey(s.key),
			[]byte(password),
			x509.PEMCipherAES256)
	} else {
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(s.key),
		}
	}
	return
}
