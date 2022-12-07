package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"simple_ca/src/x509/pkix"

	oqs "github.com/open-quantum-safe/liboqs-go/oqs"
)

var pkey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj7lVUzAXfhUs1r4L6X1+
dqZTA64Cc22Z8QRe4b2mLgaJNHx3he7Fy32a2AvkmNUD1Hz4AUyIXZvYTRM5BC+I
H86yNq4k6h3onczA+MBuzUUINt3H6diTHuoO3mpfPb9KF2WnaojURdBJ0JR4was2
2Fr2UUTgQiuw1268UjXVkc9ah6DhWGTIAlC5rrFkbY2oN0w1eQ6umcZzo+Vcs5D4
ChKosTlTGAT8k46kd9je4itQVrYSM/X9oqW1NG+HoIWmcFhKEaUTTIip+Io+o8ur
tkybWjYrJ6aL0wsghWtVLFDHwSe4cRMh/Qtvkwnbadti6Ipl/WmsyrQwG7HfXVsD
2wIDAQAB
-----END PUBLIC KEY-----`

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
	pubKey, _ := signer.GenerateKeyPair()
	fmt.Println("pubKey的值为:", pubKey[0:8])
	//生成RSA公钥
	prikey, _ := rsa.GenerateKey(rand.Reader, 128)
	rsapubkey := prikey.PublicKey

	fmt.Println("prikey的值为:", prikey)
	fmt.Println("rsapubkey的值为:", rsapubkey.N, rsapubkey.E)

	/* pkixPublicKey, _ := x509.MarshalPKIXPublicKey(rsapubkey)
	fmt.Println("pkixPublicKey的值为:", pkixPublicKey)
	pub, _ := PPK(pkixPublicKey) */
	/* pub, err := x509.ParsePKIXPublicKey([]byte(pkey))
	if err != nil {
		log.Fatal(err)
	} */
	//fmt.Println("pub的值为:", pub)

	//生成公钥

	encoded := base64.StdEncoding.EncodeToString([]byte(pubKey))

	//decoded, _ := base64.StdEncoding.DecodeString(encoded)
	/* a := asn1.BitString{Bytes: pubKey, BitLength: len(pubKey) * 8}

	fmt.Println(a.BitLength) */
	s1 := "-----BEGIN PUBLIC KEY-----"
	s2 := "-----END PUBLIC KEY-----"
	a := fmt.Sprintf("%s\n%s\n%s", s1, encoded, s2)
	fmt.Println("a的部分值:", a[0:2])
	block, _ := pem.Decode([]byte(pkey))
	pub, _ := x509.ParsePKIXPublicKey(block.Bytes)
	fmt.Println("pub的值为:", pub)
	fmt.Println("pubKey的值为:", pubKey[0:8])
	fmt.Println("block.Bytes的值为:", block.Bytes[0:16])
	fmt.Println("block的值为:", block)
	/* 	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	   	if err != nil {
	   		log.Fatal(err)
	   	}
	   	fmt.Printf("pub的值为%s", pub)*/
}
