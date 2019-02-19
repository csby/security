package certificate

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"time"
)

type RevokedItem struct {
	SerialNumber       *big.Int   `json:"serialNumber" note:"证书序号"`
	RevocationTime     time.Time  `json:"revocationTime" note:"吊销时间"`
	Organization       string     `json:"organization" note:"证书类型"`
	OrganizationalUnit string     `json:"organizationalUnit" note:"证书标识"`
	CommonName         string     `json:"common_name" note:"显示名称"`
	Locality           string     `json:"locality" note:"地区"`
	Province           string     `json:"province" note:"省份"`
	StreetAddress      string     `json:"streetAddress" note:"地址"`
	NotBefore          *time.Time `json:"notBefore" note:"起始有效期"`
	NotAfter           *time.Time `json:"notAfter" note:"截止有效期"`
}

func (s RevokedItem) String() string {
	if s.SerialNumber == nil {
		return ""
	} else {
		return s.SerialNumber.Text(16)
	}
}

func (s *RevokedItem) Extensions() []pkix.Extension {
	extensions := make([]pkix.Extension, 0)
	adder := func(extension pkix.Extension) {
		extensions = append(extensions, extension)
	}

	s.addExtension(OidOrganization, s.Organization, adder)
	s.addExtension(OidOrganizationalUnit, s.OrganizationalUnit, adder)
	s.addExtension(OidCommonName, s.CommonName, adder)
	s.addExtension(OidLocality, s.Locality, adder)
	s.addExtension(OidProvince, s.Province, adder)
	s.addExtension(OidStreetAddress, s.StreetAddress, adder)
	s.addExtension(OidNotBefore, s.NotBefore, adder)
	s.addExtension(OidNotAfter, s.NotAfter, adder)

	return extensions
}

func (s *RevokedItem) addExtension(oid asn1.ObjectIdentifier, val interface{}, adder func(extension pkix.Extension)) {
	value, err := json.Marshal(val)
	if err != nil {
		return
	}

	if adder != nil {
		adder(pkix.Extension{Id: oid, Value: value})
	}
}

type RevokedInfo struct {
	ThisUpdate *time.Time    `json:"thisUpdate" note:"本次更新时间"`
	NextUpdate *time.Time    `json:"nextUpdate" note:"下次更新时间"`
	Items      []RevokedItem `json:"items" note:"证书列表"`
}
