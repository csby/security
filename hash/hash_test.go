package hash

import "testing"

const (
	toHashData = "/api/login"
)

func TestMd5_HashToString(t *testing.T) {
	h := &Md5{}
	r, e := h.HashToString([]byte(toHashData))
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("%-8s %s", "MD5", r)
}

func TestCRC_HashToString(t *testing.T) {
	h := &CRC{}
	r, e := h.HashToString([]byte(toHashData))
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("%-8s %s", "CRC32", r)
}

func TestAdler_HashToString(t *testing.T) {
	h := &Adler{}
	r, e := h.HashToString([]byte(toHashData))
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("%-8s %s", "Adler32", r)
}
