package didutils

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/MengJi118/didutils/sm2"
)

// GenrateKeyBase58 生成公私钥对，并返回base58编码后的结果
func GenrateKeyBase58() (string, string) {
	priv, _ := sm2.GenerateKey(rand.Reader) // 生成密钥对
	privateKeyBase58 := string(Base58Encode(priv.D.Bytes()))

	pubv := sm2.Compress(&priv.PublicKey)
	publicKeyBase58 := string(Base58Encode((pubv)))

	return privateKeyBase58, publicKeyBase58
}

// SM2Sign 私钥签名
// imput为私钥（base58编码后）及带签名明文
// output为签名及错误信息
func SM2Sign(privateKey, msg string) (string, error) {
	// Private key string conversion type
	dBytes := Base58Decode([]byte(privateKey))
	pk := sm2.NewPrivateKey(dBytes)

	signByte, err := pk.Sign(rand.Reader, []byte(msg), nil)
	if err != nil {
		return "", err
	} else {
		return hex.EncodeToString(signByte), nil
	}
}

// SM2Verify 公钥验签
// input为公钥（base58编码后）、签名明文及签名
// output为验签结果布尔值
func SM2Verify(publicKey, m, signature string) bool {
	pubBytes := Base58Decode([]byte(publicKey))
	signBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	pubv := sm2.Decompress(pubBytes)
	msg := []byte(m)
	ok := pubv.Verify(msg, signBytes)
	return ok
}
