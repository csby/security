package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/csby/security/pkcs12"
	"io/ioutil"
	"os"
	"path/filepath"
)

type CrtPfx struct {
	Crt

	tlsCertificate *tls.Certificate
}

func (s *CrtPfx) PrivateKey() *RSAPrivate {
	if s.tlsCertificate == nil {
		return nil
	}
	if s.tlsCertificate.PrivateKey == nil {
		return nil
	}

	key, ok := s.tlsCertificate.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil
	}

	return &RSAPrivate{key: key}
}

func (s *CrtPfx) PublicKey() *RSAPublic {
	privateKey := s.PrivateKey()
	if privateKey == nil {
		return nil
	}

	publicKey, err := privateKey.Public()
	if err != nil {
		return nil
	}

	return publicKey
}

func (s *CrtPfx) TlsCertificates() []tls.Certificate {
	if s.tlsCertificate == nil {
		return nil
	}

	return []tls.Certificate{*s.tlsCertificate}
}

func (s *CrtPfx) FromFile(filePath, password string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	return s.FromMemory(data, password)
}

func (s *CrtPfx) FromMemory(data []byte, password string) error {
	certBlocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return err
	}

	blockData := make([]byte, 0)
	for _, b := range certBlocks {
		blockData = append(blockData, pem.EncodeToMemory(b)...)
	}

	cert, err := tls.X509KeyPair(blockData, blockData)
	if err != nil {
		return err
	}
	s.tlsCertificate = &cert

	s.certificate, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("generate x509 certificate fail: %v", err)
	}

	return nil
}

func (s *CrtPfx) ToFile(path string, ca *Crt, privateKey *RSAPrivate, password string) error {
	data, err := s.ToMemory(ca, privateKey, password)
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
	_, err = file.Write(data)

	return err
}

func (s *CrtPfx) ToMemory(ca *Crt, privateKey *RSAPrivate, password string) ([]byte, error) {
	if s.certificate == nil {
		return nil, fmt.Errorf("invalid certificate")
	}

	return pkcs12.Encode(rand.Reader, privateKey.key, s.certificate, []*x509.Certificate{ca.certificate}, password)
}
