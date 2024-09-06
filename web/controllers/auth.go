package controllers

import (
	"encoding/hex" // 用于将字节数组编码为十六进制字符串
	"time"         // 用于获取当前时间

	"ehang.io/nps/lib/crypt"   // 引入 nps 加密库
	"github.com/astaxie/beego" // 引入 Beego 框架，用于控制器和 HTTP 处理
)

// AuthController 是一个继承自 beego.Controller 的控制器，处理认证相关请求
type AuthController struct {
	beego.Controller // 嵌入 Beego 的 Controller 结构体，用于提供 HTTP 请求处理方法
}

// GetAuthKey 方法用于获取加密的认证密钥，返回加密的认证信息
func (s *AuthController) GetAuthKey() {
	// 创建一个用于存储返回数据的 map
	m := make(map[string]interface{})
	// 使用 defer 确保在函数结束时将返回数据序列化为 JSON 并返回给客户端
	defer func() {
		s.Data["json"] = m // 将数据存储在 s.Data 中，准备返回给客户端
		s.ServeJSON()      // 使用 Beego 的 ServeJSON 方法将数据序列化为 JSON 格式并返回
	}()

	// 从配置文件中读取加密密钥 auth_crypt_key，检查其长度是否为 16 字节
	if cryptKey := beego.AppConfig.String("auth_crypt_key"); len(cryptKey) != 16 {
		// 如果加密密钥长度不正确，设置返回状态为 0，表示失败
		m["status"] = 0
		return
	} else {
		// 否则，使用 AES CBC 模式加密 auth_key
		// 从配置文件中获取要加密的 auth_key
		b, err := crypt.AesEncrypt([]byte(beego.AppConfig.String("auth_key")), []byte(cryptKey))
		// 如果加密过程中出现错误，设置返回状态为 0，表示失败
		if err != nil {
			m["status"] = 0
			return
		}
		// 加密成功后，设置返回状态为 1，表示成功
		m["status"] = 1
		// 将加密后的密钥转换为十六进制字符串并存储在返回的 map 中
		m["crypt_auth_key"] = hex.EncodeToString(b)
		// 设置加密类型为 "aes cbc"
		m["crypt_type"] = "aes cbc"
		return
	}
}

// GetTime 方法用于返回当前的 Unix 时间戳
func (s *AuthController) GetTime() {
	// 创建一个 map 来存储返回的时间数据
	m := make(map[string]interface{})
	// 获取当前时间的 Unix 时间戳，并存储在 map 中
	m["time"] = time.Now().Unix()
	// 将时间数据设置为 json 响应的数据
	s.Data["json"] = m
	// 使用 Beego 的 ServeJSON 方法将数据序列化为 JSON 格式并返回给客户端
	s.ServeJSON()
}
