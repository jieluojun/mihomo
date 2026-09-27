package cns

import (
	"encoding/base64"
	"errors"
)

// Xorcrypt applies the CNS stream cipher in place and returns the next key
// position. CNS deliberately uses the same operation for encryption and
// decryption.
func Xorcrypt(data, password []byte, passwordSub int) int {
	if len(password) == 0 {
		return 0
	}

	passwordSub %= len(password)
	for i := range data {
		data[i] ^= password[passwordSub] | byte(passwordSub)
		passwordSub++
		if passwordSub == len(password) {
			passwordSub = 0
		}
	}
	return passwordSub
}

// EncryptHost encodes the target address for the CNS request header. The
// trailing NUL is part of the protocol and is removed by the server after
// decryption.
func EncryptHost(host, password string) string {
	if password == "" {
		return host
	}

	data := append([]byte(host), 0)
	Xorcrypt(data, []byte(password), 0)
	return base64.StdEncoding.EncodeToString(data)
}

// DecryptHost reverses EncryptHost. The original CNS server rejects the
// handshake when the trailing NUL is missing after XOR.
func DecryptHost(encoded, password string) (string, error) {
	if password == "" {
		return encoded, nil
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", errors.New("empty CNS host")
	}
	Xorcrypt(data, []byte(password), 0)
	if data[len(data)-1] != 0 {
		return "", errors.New("host decrypt failed")
	}
	return string(data[:len(data)-1]), nil
}
