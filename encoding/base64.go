package encoding

import "encoding/base64"

type Base64 struct {
}

func (s *Base64) EncodeToString(val []byte) string {
	return ToBase64String(val)
}

func (s *Base64) DecodeFromString(val string) ([]byte, error) {
	return FromBase64String(val)
}

func ToBase64String(val []byte) string {
	return base64.StdEncoding.EncodeToString(val)
}

func FromBase64String(val string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(val)
}
