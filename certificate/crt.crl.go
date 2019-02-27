package certificate

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

type CrtCrl struct {
	crl *pkix.CertificateList
}

func (s *CrtCrl) Info() (*RevokedInfo, error) {
	info := &RevokedInfo{
		Items: make([]RevokedItem, 0),
	}
	if s.crl == nil {
		return info, fmt.Errorf("invalid crl")
	}
	crl := &s.crl.TBSCertList
	info.ThisUpdate = &crl.ThisUpdate
	info.NextUpdate = &crl.NextUpdate

	lst := crl.RevokedCertificates
	lstCount := len(lst)
	for lstIndex := 0; lstIndex < lstCount; lstIndex++ {
		item := RevokedItem{
			SerialNumber:   lst[lstIndex].SerialNumber,
			RevocationTime: lst[lstIndex].RevocationTime,
		}

		extensions := lst[lstIndex].Extensions
		if len(extensions) > 0 {
			err := s.getExtension(extensions, OidOrganization, &item.Organization)
			if err != nil {
			}
			err = s.getExtension(extensions, OidOrganizationalUnit, &item.OrganizationalUnit)
			err = s.getExtension(extensions, OidCommonName, &item.CommonName)
			err = s.getExtension(extensions, OidLocality, &item.Locality)
			err = s.getExtension(extensions, OidProvince, &item.Province)
			err = s.getExtension(extensions, OidStreetAddress, &item.StreetAddress)
			err = s.getExtension(extensions, OidNotBefore, &item.NotBefore)
			err = s.getExtension(extensions, OidNotAfter, &item.NotAfter)
		}

		info.Items = append(info.Items, item)
	}

	return info, nil
}

func (s *CrtCrl) AddCrt(crt *Crt, revocationTime *time.Time) error {
	if crt == nil {
		return fmt.Errorf("invalid crt: nil")
	}
	if crt.certificate == nil {
		return fmt.Errorf("invalid crt: internal certificate is nil")
	}
	item := &RevokedItem{
		SerialNumber:       crt.SerialNumber(),
		RevocationTime:     time.Now(),
		Organization:       crt.Organization(),
		OrganizationalUnit: crt.OrganizationalUnit(),
		CommonName:         crt.CommonName(),
		Locality:           crt.Locality(),
		Province:           crt.Province(),
		StreetAddress:      crt.StreetAddress(),
		NotBefore:          crt.NotBefore(),
		NotAfter:           crt.NotAfter(),
	}
	if revocationTime != nil {
		item.RevocationTime = *revocationTime
	}

	return s.AddItem(item)
}

func (s *CrtCrl) AddItem(item *RevokedItem) error {
	if item == nil {
		return fmt.Errorf("parameter invalid: item is nil")
	}
	if s.crl == nil {
		s.crl = &pkix.CertificateList{
			TBSCertList: pkix.TBSCertificateList{
				RevokedCertificates: make([]pkix.RevokedCertificate, 0),
			},
		}
	}

	rc := pkix.RevokedCertificate{
		SerialNumber:   item.SerialNumber,
		RevocationTime: item.RevocationTime,
		Extensions:     item.Extensions(),
	}

	s.crl.TBSCertList.RevokedCertificates = append(s.crl.TBSCertList.RevokedCertificates, rc)
	return nil
}

func (s *CrtCrl) FromFile(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	return s.FromMemory(data)
}

func (s *CrtCrl) FromMemory(data []byte) error {
	crl, err := x509.ParseCRL(data)
	if err != nil {
		return err
	}
	s.crl = crl

	return nil
}

func (s *CrtCrl) Verify(ca *Crt) error {
	if ca == nil {
		return fmt.Errorf("invalid ca certificate")
	}
	if ca.certificate == nil {
		return fmt.Errorf("invalid ca certificate")
	}
	if s.crl == nil {
		return fmt.Errorf("invalid revocateion list")
	}

	return ca.certificate.CheckCRLSignature(s.crl)
}

func (s *CrtCrl) ToFile(path string, caCrt *Crt, caKey *RSAPrivate, thisUpdate, nextUpdate *time.Time) error {
	data, err := s.ToMemory(caCrt, caKey, thisUpdate, nextUpdate)
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

func (s *CrtCrl) ToMemory(caCrt *Crt, caKey *RSAPrivate, thisUpdate, nextUpdate *time.Time) ([]byte, error) {
	if caCrt == nil {
		return nil, fmt.Errorf("invalid ca certificate")
	}
	if caCrt.certificate == nil {
		return nil, fmt.Errorf("invalid ca certificate")
	}
	if caKey == nil {
		return nil, fmt.Errorf("invalid ca key")
	}
	if caKey.key == nil {
		return nil, fmt.Errorf("invalid ca key")
	}

	thisUpd := time.Now()
	if thisUpdate != nil {
		thisUpd = *thisUpdate
	}
	nextUpd := time.Now().AddDate(1, 0, 0)
	if nextUpdate != nil {
		nextUpd = *nextUpdate
	}

	if s.crl == nil {
		s.crl = &pkix.CertificateList{
			TBSCertList: pkix.TBSCertificateList{
				RevokedCertificates: make([]pkix.RevokedCertificate, 0),
			},
		}
	}

	data, err := caCrt.certificate.CreateCRL(rand.Reader, caKey.key, s.crl.TBSCertList.RevokedCertificates, thisUpd, nextUpd)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "X509 CRL",
		Bytes: data,
	}

	return pem.EncodeToMemory(block), nil
}

func (s *CrtCrl) getExtension(extensions []pkix.Extension, oid asn1.ObjectIdentifier, v interface{}) error {
	extLen := len(extensions)
	for idx := 0; idx < extLen; idx++ {
		if extensions[idx].Id.Equal(oid) {
			err := json.Unmarshal(extensions[idx].Value, v)
			if err != nil {
				return err
			} else {
				return nil
			}
		}
	}

	return fmt.Errorf("not found")
}
