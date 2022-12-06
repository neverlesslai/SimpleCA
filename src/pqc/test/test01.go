package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"math/big"
	"simple_ca/src/x509"
	"simple_ca/src/x509/pkix"

	oqs "github.com/open-quantum-safe/liboqs-go/oqs"
)

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}
type pkcs1PublicKey struct {
	N *big.Int
	E int
}

func PPK(derBytes []byte) (pub any, err error) {

	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		if _, err := asn1.Unmarshal(derBytes, &pkcs1PublicKey{}); err == nil {
			return nil, errors.New("x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)")
		}
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	return
}

func main() {
	sigName := "Dilithium2"
	signer := oqs.Signature{}
	defer signer.Clean() // clean up even in case of panic

	/* if err := signer.Init(sigName, nil); err != nil {
		log.Fatal(err)
	} */
	if err := signer.Init(sigName, nil); err != nil {
		log.Fatal(err)
	}
	//pubKey, _ := signer.GenerateKeyPair()
	//生成RSA公钥
	prikey, _ := rsa.GenerateKey(rand.Reader, 128)
	rsapubkey := prikey.PublicKey

	fmt.Println("prikey的值为:", prikey)
	fmt.Println("rsapubkey的值为:", rsapubkey.N, rsapubkey.E)

	pkixPublicKey, _ := x509.MarshalPKIXPublicKey(rsapubkey)
	fmt.Println("pkixPublicKey的值为:", pkixPublicKey)
	pub, _ := PPK(pkixPublicKey)
	/* pub, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		log.Fatal(err)
	} */
	fmt.Println("pub的值为:", pub)

	//生成公钥

	//encoded := base64.StdEncoding.EncodeToString([]byte(pubKey))
	/* a := asn1.BitString{Bytes: pubKey, BitLength: len(pubKey) * 8}
	fmt.Println(len(pubKey))
	fmt.Println(a.BitLength) */
	/* s1 := "-----BEGIN PUBLIC KEY-----"
	s2 := "-----END PUBLIC KEY-----"
	a := fmt.Sprintf("%s\n%s\n%s", s1, encoded, s2)
	block, _ := pem.Decode([]byte(a))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", pub) */
}
