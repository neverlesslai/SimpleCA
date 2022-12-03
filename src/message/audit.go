package message

import (
	"simple_ca/src/definition"

	ginTools "github.com/520MianXiangDuiXiang520/ginUtils"
	"github.com/gin-gonic/gin"
)

type CRSPublicKey struct {
	ID        uint   `json:"id"`
	PublicKey string `json:"public_key"`
	TypeStr   string `json:"type_str"`
	definition.CertificateSigningRequest
}

type AuditListResp struct {
	Header  ginTools.BaseRespHeader `json:"header"`
	CRSList []CRSPublicKey          `json:"crs_list"`
}
type AuditBetaResp struct {
	Header ginTools.BaseRespHeader `json:"header"`
}
type AuditBetaReq struct {
	CSRID uint `json:"csr_id"`
}

func (r *AuditBetaReq) JSON(ctx *gin.Context) error {
	return ctx.ShouldBindJSON(&r)
}

type AuditListReq struct {
}

func (r *AuditListReq) JSON(ctx *gin.Context) error {
	return ctx.ShouldBindJSON(&r)
}

type AuditPassResp struct {
	Header ginTools.BaseRespHeader `json:"header"`
}

type AuditPassReq struct {
	CSRID uint `json:"csr_id"` // CSR ID, 接口属于管理员，无需加密
}

func (r *AuditPassReq) JSON(ctx *gin.Context) error {
	return ctx.ShouldBindJSON(&r)
}

type AuditUnPassResp struct {
	Header ginTools.BaseRespHeader `json:"header"`
}

type AuditUnPassReq struct {
	CSRID uint `json:"csr_id"` // CSR ID 3DES 加密后 Base64 编码
}

func (r *AuditUnPassReq) JSON(ctx *gin.Context) error {
	return ctx.ShouldBindJSON(&r)
}
