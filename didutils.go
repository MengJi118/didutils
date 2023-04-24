package didutils

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/MengJi118/didutils/sm2"
)

// SM2Sign 私钥签名
// imput为私钥的十六进制编码格式（hex.EncodeToString(b)）及带签名明文
// output为签名及错误信息
func SM2Sign(privateKey, msg string) (string, error) {
	// Private key string conversion type
	dBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", err
	}
	pk := sm2.NewPrivateKey(dBytes)

	signByte, err := pk.Sign(rand.Reader, []byte(msg), nil)
	if err != nil {
		return "", err
	} else {
		return hex.EncodeToString(signByte), nil
	}
}

// SM2Verify 公钥验签
// input为公钥的十六进制编码格式（hex.EncodeToString(b)）、签名明文及签名
// output为验签结果布尔值
func SM2Verify(publicKey, m, signature string) bool {
	pubBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return false
	}
	signBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	pubv := sm2.Decompress(pubBytes)
	msg := []byte(m)
	ok := pubv.Verify(msg, signBytes)
	return ok
}
