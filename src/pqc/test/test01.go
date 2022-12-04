package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"

	oqs "github.com/open-quantum-safe/liboqs-go/oqs"
)

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
	//生成公钥
	pubKey, err := signer.GenerateKeyPair()
	encoded := base64.StdEncoding.EncodeToString([]byte(pubKey))
	s1 := "-----BEGIN PUBLIC KEY-----"
	s2 := "-----END PUBLIC KEY-----"
	a := fmt.Sprintf("%s\n%s\n%s", s1, encoded, s2)
	block, _ := pem.Decode([]byte(a))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", pub)
}
