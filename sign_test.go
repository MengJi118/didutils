package didutils

import (
	"testing"
)

func TestSign(t *testing.T) {
	data := "12345678"

	privateKeyBase58, publicKeyBase58 := GenrateKeyBase58()

	sign, err := SM2Sign(privateKeyBase58, data)
	if err != nil {
		t.Fatalf("bad: %s", err)
	}

	result := SM2Verify(publicKeyBase58, data, sign)
	if result != true {
		t.Fatalf("bad: 验签失败")
	}
}
