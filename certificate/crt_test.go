package certificate

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCrt_Create(t *testing.T) {
	caCrt, caPrivate, err := testCreateCA()
	if err != nil {
		t.Fatal(err)
	}

	serverCrt, _, err := testCreateServer(caCrt, caPrivate)
	if err != nil {
		t.Fatal(err)
	}

	clientCrt, _, err := testCreateClient(caCrt, caPrivate)
	if err != nil {
		t.Fatal(err)
	}

	crl := &CrtCrl{}
	err = crl.AddCrt(&serverCrt.Crt, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = crl.AddCrt(&clientCrt.Crt, nil)
	if err != nil {
		t.Fatal(err)
	}

	folder := testFileFolder()
	err = crl.ToFile(filepath.Join(folder, "cr.crl"), caCrt, caPrivate, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCrt_End(t *testing.T) {
	folder := testFileFolder()
	os.RemoveAll(folder)
}

func testCreateCA() (*Crt, *RSAPrivate, error) {
	folder := testFileFolder()

	private := &RSAPrivate{Format: "pkcs8"}
	err := private.Create(2048)
	if err != nil {
		return nil, nil, err
	}
	err = private.ToFile(filepath.Join(folder, "ca.key"), "")
	if err != nil {
		return nil, nil, err
	}
	public, err := private.Public()
	if err != nil {
		return nil, nil, err
	}

	crtTemplate := &CrtTemplate{
		Organization:       "ca",
		OrganizationalUnit: "sgw",
		Locality:           "华东",
		Province:           "浙江",
		StreetAddress:      "杭州",
	}
	template, err := crtTemplate.Template()
	if err != nil {
		return nil, nil, err
	}

	crt := &Crt{}
	err = crt.Create(template, template, public, private)
	if err != nil {
		return nil, nil, err
	}

	err = crt.ToFile(filepath.Join(folder, "ca.crt"))
	if err != nil {
		return nil, nil, err
	}

	return crt, private, err
}

func testCreateServer(caCrt *Crt, caPrivate *RSAPrivate) (*CrtPfx, *RSAPrivate, error) {
	folder := testFileFolder()

	private := &RSAPrivate{}
	err := private.Create(2048)
	if err != nil {
		return nil, nil, err
	}
	err = private.ToFile(filepath.Join(folder, "server.key"), "server")
	if err != nil {
		return nil, nil, err
	}
	public, err := private.Public()
	if err != nil {
		return nil, nil, err
	}

	crtTemplate := &CrtTemplate{
		Organization:       "server",
		OrganizationalUnit: "vs",
		Locality:           "华东",
		Province:           "浙江",
		StreetAddress:      "杭州1",
		Hosts: []string{
			"127.0.0.1",
			"server.example.com",
		},
	}
	template, err := crtTemplate.Template()
	if err != nil {
		return nil, nil, err
	}

	crt := &CrtPfx{}
	err = crt.Create(template, caCrt.certificate, public, caPrivate)
	if err != nil {
		return nil, nil, err
	}

	err = crt.Crt.ToFile(filepath.Join(folder, "server.crt"))
	if err != nil {
		return nil, nil, err
	}

	err = crt.ToFile(filepath.Join(folder, "server.pfx"), caCrt, private, "server")
	if err != nil {
		return nil, nil, err
	}

	err = crt.FromFile(filepath.Join(folder, "server.pfx"), "server")
	if err != nil {
		return nil, nil, err
	}

	return crt, private, err
}

func testCreateClient(caCrt *Crt, caPrivate *RSAPrivate) (*CrtPfx, *RSAPrivate, error) {
	folder := testFileFolder()

	private := &RSAPrivate{}
	err := private.Create(2048)
	if err != nil {
		return nil, nil, err
	}
	err = private.ToFile(filepath.Join(folder, "client.key"), "")
	if err != nil {
		return nil, nil, err
	}
	public, err := private.Public()
	if err != nil {
		return nil, nil, err
	}

	crtTemplate := &CrtTemplate{
		Organization:       "client",
		OrganizationalUnit: "hospital",
		Locality:           "华东",
		Province:           "浙江",
		StreetAddress:      "杭州2",
	}
	template, err := crtTemplate.Template()
	if err != nil {
		return nil, nil, err
	}

	crt := &CrtPfx{}
	err = crt.Create(template, caCrt.certificate, public, caPrivate)
	if err != nil {
		return nil, nil, err
	}

	err = crt.Crt.ToFile(filepath.Join(folder, "client.crt"))
	if err != nil {
		return nil, nil, err
	}

	return crt, private, err
}

func testFileFolder() string {
	_, file, _, _ := runtime.Caller(0)

	return filepath.Join(filepath.Dir(file), "crt")
}
