package didutils

const didPrefix string = "did:ctid"

// DID文档
type DidDocument struct {
	Context        []string
	Id             string
	Version        string
	PublicKey      []PublicKey
	Authentication []string
	Proof          DocumentProof
	Service        []Service
}

type DocumentProof struct {
	Type           string
	Created        string
	Updated        string
	Creator        string
	SignatureValue string
}

type PublicKey struct {
	Id              string
	Type            string
	Controller      string
	PublicKeyBase58 string
}

type Service struct {
	Id              string
	Type            string
	ServiceEndpoint string
}
