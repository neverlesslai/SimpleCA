package main

import (
	"simple_ca/src/middleware"
	"simple_ca/src/routes"

	ginTools "github.com/520MianXiangDuiXiang520/ginUtils"
	"github.com/gin-gonic/gin"
)

func Register(c *gin.Engine) {
	c.Use(middleware.CorsHandler())
	//申请证书路由
	ginTools.URLPatterns(c, "api/ca", routes.CARegister)
	//用户登录路由
	ginTools.URLPatterns(c, "api/auth", routes.AuthRegister)
	//证书签名界面
	ginTools.URLPatterns(c, "api/audit", routes.AuditRegister)
	//查看证书界面
	ginTools.URLPatterns(c, "api/user", routes.UserRegister)
}
