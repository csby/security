package certificate

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"time"
)

type CrtTemplate struct {
	// 显示名称
	CommonName string

	// 证书类型
	// ca：根证书
	// server：服务器证书
	// client：客户端证书
	// user：用户证书
	Organization string

	// 证书标识，依赖证书类型
	// |========|===============|
	// |证书类型	|证书标识含义	 |
	// |========|===============|
	// |ca		|CA名称			 |
	// |--------|---------------|
	// |server	|服务器名称		 |
	// |--------|---------------|
	// |client	|客户端标识		 |
	// |--------|---------------|
	// |user	|用户标识		 |
	// |========|===============|
	OrganizationalUnit string

	// 地区
	Locality string
	// 省份
	Province string
	// 地址
	StreetAddress string

	// 使用者可选标识(针对具有服务器身份验证的证书)
	Hosts []string

	// 扩展信息
	Extensions []pkix.Extension

	// 有效期(默认365)
	ExpiredDays int64
}

func (s *CrtTemplate) Template() (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	isCA := false
	commonName := s.CommonName
	if commonName == "" {
		commonName = s.OrganizationalUnit
	}
	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	ips := make([]net.IP, 0)
	dns := make([]string, 0)

	notBefore := time.Now()
	days := s.ExpiredDays
	if days < 1 {
		days = 365
	}
	notAfter := notBefore.Add(time.Duration(days * 24 * time.Hour.Nanoseconds()))

	if strings.ToLower(s.Organization) == "ca" {
		isCA = true
		keyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
		extKeyUsage = nil
	} else if strings.ToLower(s.Organization) == "server" {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if len(s.Hosts) > 0 {
			for _, h := range s.Hosts {
				if ip := net.ParseIP(h); ip != nil {
					ips = append(ips, ip)
				} else {
					dns = append(dns, h)
				}
			}
		}
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{s.Organization},
			OrganizationalUnit: []string{s.OrganizationalUnit},

			Locality:      []string{s.Locality},
			Province:      []string{s.Province},
			StreetAddress: []string{s.StreetAddress},

			CommonName: commonName,
		},

		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,

		IsCA:        isCA,
		KeyUsage:    keyUsage,
		ExtKeyUsage: extKeyUsage,

		IPAddresses: ips,
		DNSNames:    dns,

		ExtraExtensions: s.Extensions,
	}

	return template, nil
}
