package pqc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"
	"simple_ca/src/x509"
	"simple_ca/src/x509/pkix"
	"time"
)

// 生成代码签名证书
func CreateCodeSignCert(rootCer *x509.Certificate, serialN *big.Int, subject pkix.Name,
	publicKey string, pk *rsa.PrivateKey, notBefore, notAfter time.Time,
	CRLDistributionPoint []string, p string) bool {
	template := &x509.Certificate{
		Version:               1,
		SerialNumber:          serialN,
		Subject:               subject,
		Issuer:                subject,
		SignatureAlgorithm:    x509.SignedwithDilithium2,
		PublicKeyAlgorithm:    x509.Dilithium2,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		CRLDistributionPoints: CRLDistributionPoint,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	return createNewCertificate(rootCer, template, publicKey, pk, p)
}

//创建新证书
func createNewCertificate(rootCer, template *x509.Certificate,
	publicKey string, pk *rsa.PrivateKey, p string) bool {

	var c []byte
	var err error
	/* // 生成根证书
	if rootCer == nil {
		c, err = x509.CreatepqcCertificate(rand.Reader, template, template, &pk.PublicKey, pk)
	} else { */
	//生成对应格式的公钥
	pub, ok := DecodeRSAPublicKey([]byte(publicKey))
	if !ok {
		return false
	}
	//如果上传了根证书就走这个路由
	c, err = x509.CreatepqcCertificate(rand.Reader, template, template, pub)

	if err != nil {
		ExceptionLog(err, "Failed to create certificate")
		return false
	}
	fileObj3, _ := os.OpenFile("./pubkey.pem", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	fmt.Fprintf(fileObj3, "%s", c)
	//创建接收base64DER格式的文件
	certOut, err := os.Create(p)
	if err != nil {
		ExceptionLog(err, fmt.Sprintf("Failed to create %s", p))
		return false
	}
	//编码将 pem.Block 的 PEM 编码写入certOut。
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: c})
	if err != nil {
		ExceptionLog(err, fmt.Sprintf("Failed to encode pem"))
		return false
	}
	certOut.Close()
	return true
}

// 解码 RSA 公钥 pem 文件
func DecodeRSAPublicKey(input []byte) ([]byte, bool) {
	//找到 PEM 格式的块（证书、私钥等）。它返回该块和输入的其余部分。如果未找到 PEM 数据，则 p 为零，并且整个输入以静止状态返回。
	block, _ := pem.Decode(input)
	if block == nil || (block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY") {
		ExceptionLog(errors.New("DecodeRSAPublicKeyFail"),
			"failed to decode PEM block containing public key")
		return nil, false
	}
	/* pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		ExceptionLog(errors.New("ParsePKIXPublicKeyFail"),
			"failed to parse PKIX public key")
		return nil, false
	} */
	pub := block.Bytes
	return pub, true
}

func ExceptionLog(e error, mes string) {
	if e != nil {
		pc, _, line, _ := runtime.Caller(1)
		fName := runtime.FuncForPC(pc).Name()
		log.Printf("[Error] %v:%v  %v", fName, line, mes)
		log.Printf("[Error] %v", e)
	}
}
