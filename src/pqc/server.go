package pqc

import (
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"simple_ca/src"
	"simple_ca/src/dao"
	"simple_ca/src/definition"
	"simple_ca/src/message"
	"simple_ca/src/tools"
	"strings"
	"time"

	ginTools "github.com/520MianXiangDuiXiang520/ginUtils"
	"github.com/gin-gonic/gin"
)

func AuditBetaLogic(ctx *gin.Context, req ginTools.BaseReqInter) ginTools.BaseRespInter {
	request := req.(*message.AuditPassReq)
	resp := message.AuditPassResp{}
	// 删除解密步骤(2020/11/29)
	// csr, ok := checkCSRID(request.CSRID)
	csr, ok := dao.GetCRSByID(request.CSRID)
	if !ok {
		resp.Header = ginTools.ParamErrorRespHeader
		return resp
	}

	if csr.State != definition.CRSStateAuditing {
		resp.Header = ginTools.ParamErrorRespHeader
		return resp
	}

	// 修改 CSR 状态
	csr, ok = dao.SetCSRState(csr, definition.CRSStatePass)
	if !ok {
		resp.Header = ginTools.SystemErrorRespHeader
		return resp
	}

	user, ok := dao.HasUserByID(csr.UserID)
	if !ok {
		resp.Header = ginTools.SystemErrorRespHeader
		return resp
	}

	notBefore := time.Now()
	// 证书有效时间为 365 天
	notAfter := time.Now().Add(time.Hour * 24 * 365)
	expireTime := time.Now().Unix() + definition.WrongOneYear

	// 落库存储
	c, ok := dao.CreateNewCertificate(&dao.Certificate{
		State:      definition.CertificateStateUsing,
		ExpireTime: expireTime,
		UserID:     csr.UserID,
		RequestID:  csr.ID,
	})
	// 生成证书
	cName := tools.GetCertificateFileName(c.ID, user.ID, user.Username)
	cerFileName := fmt.Sprintf("%s/%s",
		src.GetSetting().Secret.UserCerPath, cName)
	// 获取 CA 根证书和私钥
	rootCer, rootPK := src.GetCARootCer()

	subject := pkix.Name{
		Country:            []string{csr.Country},
		Province:           []string{csr.Province},
		Locality:           []string{csr.Locality},
		Organization:       []string{csr.Organization},
		OrganizationalUnit: []string{csr.OrganizationUnitName},
		CommonName:         csr.CommonName,
	}
	crlDP := []string{src.GetSetting().CRLSetting.CRLDistributionPoint}

	switch csr.Type {
	// 签发代码签名证书
	case definition.CertificateTypeCodeSign:
		ok = tools.CreateCodeSignCert(&rootCer, big.NewInt(int64(int(c.ID))), subject,
			csr.PublicKey, &rootPK, notBefore, notAfter, crlDP, cerFileName)
	// 签发 SSL 证书
	case definition.CertificateTypeSSL:
		dnsNames := strings.Split(csr.DnsNames, " ")
		ok = tools.CreateSSLCert(&rootCer, big.NewInt(int64(int(c.ID))), subject,
			csr.PublicKey, &rootPK, notBefore, notAfter, crlDP, dnsNames, cerFileName)
	default:
		resp.Header = ginTools.ParamErrorRespHeader
		return resp
	}
	if !ok {
		resp.Header = ginTools.BaseRespHeader{
			Code: http.StatusInternalServerError,
			Msg:  "证书生成失败！",
		}
		return resp
	}
	// 邮件通知用户
	emailTemp := definition.CerSuccessTemp(map[string]string{
		"siteLink":    src.GetSetting().SiteLink,
		"username":    user.Username,
		"requestTime": csr.CreatedAt.Format("2006-01-02 15:04:05"),
		"time":        time.Now().Format("2006-01-02 15:04:05"),
	})
	err := email_tools.Send(&email_tools.Context{
		ToList: []email_tools.Role{
			{Address: user.Email, Name: user.Username},
		},
		Subject: "证书申请通过通知",
		Body:    emailTemp,
		Path:    cerFileName,
	})
	if err != nil {
		resp.Header = ginTools.BaseRespHeader{
			Code: http.StatusInternalServerError,
			Msg:  "证书申请已通过，但颁发失败，请联系用户：" + user.Email,
		}
		return resp
	}
	resp.Header = ginTools.SuccessRespHeader
	return resp
}
