// security project security.go
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

type Aes struct {
	Key      string
	CommonIv string
}

func (obj Aes) Encrypt(byteArray []byte) (returnValue []byte, returnError error) {
	defer func() {
		if err := recover(); err != nil {
			returnError = fmt.Errorf("%v", err)
		}
	}()
	c, err := aes.NewCipher([]byte(obj.Key))
	if err != nil {
		returnError = err
		return
	}
	cfb := cipher.NewCFBEncrypter(c, []byte(obj.CommonIv))
	cipherText := make([]byte, len(byteArray))
	cfb.XORKeyStream(cipherText, byteArray)
	returnValue = cipherText
	return
}

func (obj Aes) Decrypt(byteArray []byte) (returnValue []byte, returnError error) {
	defer func() {
		if err := recover(); err != nil {
			returnError = fmt.Errorf("%v", err)
		}
	}()
	c, err := aes.NewCipher([]byte(obj.Key))
	if err != nil {
		returnError = err
		return
	}
	cfbdec := cipher.NewCFBDecrypter(c, []byte(obj.CommonIv))
	plainText := make([]byte, len(byteArray))
	cfbdec.XORKeyStream(plainText, byteArray)
	returnValue = plainText
	return
}
