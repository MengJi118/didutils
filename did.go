package didutils

import (
	"crypto/sha256"
	"time"

	"golang.org/x/crypto/ripemd160"
)

const VERSION = byte(0x00)
const CHECKSUM_LENGTH = 4

// getDidMethod 计算did标识
func getDidMethod(publicKey string) []byte {
	//1.ripemd160(sha256(publickey))
	ripPubKey := generatePublicKeyHash([]byte(publicKey))
	//2.最前面添加一个字节的版本信息获得 versionPublickeyHash
	versionPublickeyHash := append([]byte{VERSION}, ripPubKey[:]...)
	//3.sha256(sha256(versionPublickeyHash))  取最后四个字节的值
	tailHash := checkSumHash(versionPublickeyHash)
	//4.拼接最终hash versionPublickeyHash + checksumHash
	finalHash := append(versionPublickeyHash, tailHash...)
	//进行base58加密
	address := Base58Encode(finalHash)
	return address
}

func generatePublicKeyHash(publicKey []byte) []byte {
	sha256PubKey := sha256.Sum256(publicKey)
	r := ripemd160.New()
	r.Write(sha256PubKey[:])
	ripPubKey := r.Sum(nil)
	return ripPubKey
}

func checkSumHash(versionPublickeyHash []byte) []byte {
	versionPublickeyHashSha1 := sha256.Sum256(versionPublickeyHash)
	versionPublickeyHashSha2 := sha256.Sum256(versionPublickeyHashSha1[:])
	tailHash := versionPublickeyHashSha2[:CHECKSUM_LENGTH]
	return tailHash
}

// GetDidDocument 获取did文档
// input为公钥及类型
// output为did文档
func GetDidDocument(publicKeyBase58, keyType string) DidDocument {
	didMethod := getDidMethod(publicKeyBase58)

	return DidDocument{
		Context: []string{"https://www.w3.org/2018/credentials/v1"},
		Id:      didPrefix + string(didMethod),
		Version: "1.0",
		PublicKey: []PublicKey{
			{
				Id:              "#key0",
				Type:            keyType,
				Controller:      didPrefix + string(didMethod),
				PublicKeyBase58: publicKeyBase58,
			},
		},
		Authentication: []string{""},
		Proof: DocumentProof{
			Type:    keyType,
			Created: time.Now().Format("2006-01-02 15:04:05"),
			Updated: time.Now().Format("2006-01-02 15:04:05"),
			Creator: didPrefix + string(didMethod),
		},
		Service: []Service{},
	}
}
