package controllers

import (
	"strings"

	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/file"
	"ehang.io/nps/lib/rate"
	"ehang.io/nps/server"
	"github.com/astaxie/beego"
)

type ClientController struct {
	BaseController
}

func (s *ClientController) List() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "client"
		s.SetInfo("client")
		s.display("client/list")
		return
	}
	start, length := s.GetAjaxParams()
	clientIdSession := s.GetSession("clientId")
	var clientId int
	if clientIdSession == nil {
		clientId = 0
	} else {
		clientId = clientIdSession.(int)
	}
	list, cnt := server.GetClientList(start, length, s.getEscapeString("search"), s.getEscapeString("sort"), s.getEscapeString("order"), clientId)
	cmd := make(map[string]interface{})
	ip := s.Ctx.Request.Host
	cmd["ip"] = common.GetIpByAddr(ip)
	cmd["bridgeType"] = beego.AppConfig.String("bridge_type")
	cmd["bridgePort"] = server.Bridge.TunnelPort
	s.AjaxTable(list, cnt, cnt, cmd)
}

// 添加客户端
func (s *ClientController) Add() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "client"
		s.SetInfo("add client")
		s.display()
	} else {
		id := int(file.GetDb().JsonDb.GetClientId())
		t := &file.Client{
			VerifyKey: s.getEscapeString("vkey"),
			Id:        id,
			Status:    true,
			Remark:    s.getEscapeString("remark"),
			Cnf: &file.Config{
				U:        s.getEscapeString("u"),
				P:        s.getEscapeString("p"),
				Compress: common.GetBoolByStr(s.getEscapeString("compress")),
				Crypt:    s.GetBoolNoErr("crypt"),
			},
			ConfigConnAllow: s.GetBoolNoErr("config_conn_allow"),
			RateLimit:       s.GetIntNoErr("rate_limit"),
			MaxConn:         s.GetIntNoErr("max_conn"),
			WebUserName:     s.getEscapeString("web_username"),
			WebPassword:     s.getEscapeString("web_password"),
			MaxTunnelNum:    s.GetIntNoErr("max_tunnel"),
			Flow: &file.Flow{
				ExportFlow: 0,
				InletFlow:  0,
				FlowLimit:  int64(s.GetIntNoErr("flow_limit")),
			},
			BlackIpList: RemoveRepeatedElement(strings.Split(s.getEscapeString("blackiplist"), "\r\n")),
		}
		if err := file.GetDb().NewClient(t); err != nil {
			s.AjaxErr(err.Error())
		}
		s.AjaxOkWithId("add success", id)
	}
}

// 查询单个客户端信息
func (s *ClientController) GetClient() {
	if s.Ctx.Request.Method == "POST" {
		id := s.GetIntNoErr("id")
		data := make(map[string]interface{})
		if c, err := file.GetDb().GetClient(id); err != nil {
			data["code"] = 0
		} else {
			data["code"] = 1
			data["data"] = c
		}
		s.Data["json"] = data
		s.ServeJSON()
	}
}

// 查询单个客户端流量信息
func (s *ClientController) GetClientll() {
	if s.Ctx.Request.Method == "POST" {
		id := s.GetIntNoErr("id")
		data := make(map[string]interface{})
		if c, err := file.GetDb().GetClient(id); err != nil {
			data["code"] = 0
		} else {
			data["code"] = 1
			// 提取 Id, VerifyKey, ExportFlow 和 InletFlow 字段
			clientData := map[string]interface{}{
				"Id":         c.Id,
				"VerifyKey":  c.VerifyKey,
				"ExportFlow": c.Flow.ExportFlow,
				"InletFlow":  c.Flow.InletFlow,
			}
			data["data"] = clientData
		}
		s.Data["json"] = data
		s.ServeJSON()
	}
}

// 修改客户端
func (s *ClientController) Edit() {
	// 从请求上下文中获取 "id" 参数，并将其解析为整数
	id := s.GetIntNoErr("id")
	// 检查 HTTP 请求方法是否为 'GET'
	if s.Ctx.Request.Method == "GET" {
		// 设置当前菜单上下文为 "client"
		s.Data["menu"] = "client"
		// 使用提供的 'id' 从数据库获取客户数据
		if c, err := file.GetDb().GetClient(id); err != nil {
			// 如果获取客户时发生错误，处理错误
			s.error()
		} else {
			// 如果成功获取客户，将客户数据存储在响应中
			s.Data["c"] = c
			// 将 BlackIpList 从切片转换为字符串，每个 IP 在新行上
			s.Data["BlackIpList"] = strings.Join(c.BlackIpList, "\r\n")
		}
		// 设置操作的提示信息
		s.SetInfo("edit client")
		// 显示编辑客户页面
		s.display()
	} else {
		// 处理 HTTP 请求方法不是 'GET' 的情况（假设是 'POST'）
		// 使用提供的 'id' 再次获取客户数据
		if c, err := file.GetDb().GetClient(id); err != nil {
			// 如果获取客户时发生错误，处理错误并返回 Ajax 错误响应
			s.error()
			s.AjaxErr("client ID not found")
			return
		} else {
			// 如果成功获取客户，继续处理
			// 检查 web 用户名字段是否不为空
			if s.getEscapeString("web_username") != "" {
				// 验证 web 用户名是否符合预定义设置和现有用户名
				if s.getEscapeString("web_username") == beego.AppConfig.String("web_username") || !file.GetDb().VerifyUserName(s.getEscapeString("web_username"), c.Id) {
					// 如果用户名重复或无效，返回 Ajax 错误响应
					s.AjaxErr("web login username duplicate, please reset")
					return
				}
			}
			// 检查当前会话是否具有管理员权限
			if s.GetSession("isAdmin").(bool) {
				// 验证 vkey（验证密钥）以确保它不是重复的
				if !file.GetDb().VerifyVkey(s.getEscapeString("vkey"), c.Id) {
					// 如果 vkey 是重复的，返回 Ajax 错误响应
					s.AjaxErr("Vkey duplicate, please reset")
					return
				}
				// 使用请求中的新值更新客户详情
				c.VerifyKey = s.getEscapeString("vkey")
				c.Flow.FlowLimit = int64(s.GetIntNoErr("flow_limit"))
				c.RateLimit = s.GetIntNoErr("rate_limit")
				c.MaxConn = s.GetIntNoErr("max_conn")
				c.MaxTunnelNum = s.GetIntNoErr("max_tunnel")
			}
			// 从请求参数中更新客户的其他详细信息
			c.Remark = s.getEscapeString("remark")
			c.Cnf.U = s.getEscapeString("u")
			c.Cnf.P = s.getEscapeString("p")
			c.Cnf.Compress = common.GetBoolByStr(s.getEscapeString("compress"))
			c.Cnf.Crypt = s.GetBoolNoErr("crypt")
			// 根据配置设置确定用户是否可以更改用户名
			b, err := beego.AppConfig.Bool("allow_user_change_username")
			if s.GetSession("isAdmin").(bool) || (err == nil && b) {
				c.WebUserName = s.getEscapeString("web_username")
			}
			// 从请求参数中更新客户的 web 密码
			c.WebPassword = s.getEscapeString("web_password")
			// 从请求参数中更新客户的连接配置
			c.ConfigConnAllow = s.GetBoolNoErr("config_conn_allow")
			// 如果有现有的速率限制器，停止它
			if c.Rate != nil {
				c.Rate.Stop()
			}
			// 根据速率限制参数设置新的速率限制
			if c.RateLimit > 0 {
				c.Rate = rate.NewRate(int64(c.RateLimit * 1024)) // 将 KB 转换为字节
				c.Rate.Start()                                   // 以新的限制启动速率限制器
			} else {
				c.Rate = rate.NewRate(int64(2 << 23)) // 如果未提供，则使用默认的速率限制
				c.Rate.Start()                        // 以默认限制启动速率限制器
			}
			// 更新客户的黑名单 IP 列表，去除重复项
			c.BlackIpList = RemoveRepeatedElement(strings.Split(s.getEscapeString("blackiplist"), "\r\n"))
			// 将更新后的客户数据存储回 JSON 文件
			file.GetDb().JsonDb.StoreClientsToJsonFile()
		}
		// 返回成功消息给客户
		s.AjaxOk("save success")
	}
}

// 修改客户端
func (s *ClientController) TestEdit() {
	// 从请求上下文中获取 "id" 参数，并将其解析为整数
	id := s.GetIntNoErr("id")
	// 检查 HTTP 请求方法是否为 'GET'
	if s.Ctx.Request.Method == "GET" {
		// 设置当前菜单上下文为 "client"
		s.Data["menu"] = "client"
		// 使用提供的 'id' 从数据库获取客户数据
		if c, err := file.GetDb().GetClient(id); err != nil {
			// 如果获取客户时发生错误，处理错误
			s.error()
		} else {
			// 如果成功获取客户，将客户数据存储在响应中
			s.Data["c"] = c
			// 将 BlackIpList 从切片转换为字符串，每个 IP 在新行上
			s.Data["BlackIpList"] = strings.Join(c.BlackIpList, "\r\n")
		}
		// 设置操作的提示信息
		s.SetInfo("edit client")
		// 显示编辑客户页面
		s.display()
	} else {
		// 处理 HTTP 请求方法不是 'GET' 的情况（假设是 'POST'）
		// 使用提供的 'id' 再次获取客户数据
		if c, err := file.GetDb().GetClient(id); err != nil {
			// 如果获取客户时发生错误，处理错误并返回 Ajax 错误响应
			s.error()
			s.AjaxErr("client ID not found")
			return
		} else {
			// 如果成功获取客户，继续处理
			// 检查 web 用户名字段是否不为空
			if s.getEscapeString("web_username") != "" {
				// 验证 web 用户名是否符合预定义设置和现有用户名
				if s.getEscapeString("web_username") == beego.AppConfig.String("web_username") || !file.GetDb().VerifyUserName(s.getEscapeString("web_username"), c.Id) {
					// 如果用户名重复或无效，返回 Ajax 错误响应
					s.AjaxErr("web login username duplicate, please reset")
					return
				}
			}
			// 检查当前会话是否具有管理员权限
			if s.GetSession("isAdmin").(bool) {
				// 验证 vkey（验证密钥）以确保它不是重复的
				if !file.GetDb().VerifyVkey(s.getEscapeString("vkey"), c.Id) {
					// 如果 vkey 是重复的，返回 Ajax 错误响应
					s.AjaxErr("Vkey duplicate, please reset")
					return
				}
				// 使用请求中的新值更新客户详情
				c.VerifyKey = s.getEscapeString("vkey")
				c.Flow.FlowLimit = int64(s.GetIntNoErr("flow_limit"))
				c.RateLimit = s.GetIntNoErr("rate_limit")
				c.MaxConn = s.GetIntNoErr("max_conn")
				c.MaxTunnelNum = s.GetIntNoErr("max_tunnel")
			}
			// 从请求参数中更新客户的其他详细信息
			c.Remark = s.getEscapeString("remark")
			c.Cnf.U = s.getEscapeString("u")
			c.Cnf.P = s.getEscapeString("p")
			c.Cnf.Compress = common.GetBoolByStr(s.getEscapeString("compress"))
			c.Cnf.Crypt = s.GetBoolNoErr("crypt")
			// 根据配置设置确定用户是否可以更改用户名
			b, err := beego.AppConfig.Bool("allow_user_change_username")
			if s.GetSession("isAdmin").(bool) || (err == nil && b) {
				c.WebUserName = s.getEscapeString("web_username")
			}
			// 从请求参数中更新客户的 web 密码
			c.WebPassword = s.getEscapeString("web_password")
			// 从请求参数中更新客户的连接配置
			c.ConfigConnAllow = s.GetBoolNoErr("config_conn_allow")
			// 如果有现有的速率限制器，停止它
			if c.Rate != nil {
				c.Rate.Stop()
			}
			// 根据速率限制参数设置新的速率限制
			if c.RateLimit > 0 {
				c.Rate = rate.NewRate(int64(c.RateLimit * 1024)) // 将 KB 转换为字节
				c.Rate.Start()                                   // 以新的限制启动速率限制器
			} else {
				c.Rate = rate.NewRate(int64(2 << 23)) // 如果未提供，则使用默认的速率限制
				c.Rate.Start()                        // 以默认限制启动速率限制器
			}
			// 更新客户的黑名单 IP 列表，去除重复项
			c.BlackIpList = RemoveRepeatedElement(strings.Split(s.getEscapeString("blackiplist"), "\r\n"))
			// 将更新后的客户数据存储回 JSON 文件
			file.GetDb().JsonDb.StoreClientsToJsonFile()
		}
		// 返回成功消息给客户
		s.AjaxOk("save success")
	}
}

// 重置客户端流量限速
func (s *ClientController) Mnatedit() {
	// 从请求上下文中获取 "id" 参数，并将其解析为整数
	id := s.GetIntNoErr("id")
	// 检查 HTTP 请求方法是否为 'GET'
	if s.Ctx.Request.Method == "POST" {
		// 处理 HTTP 请求方法不是 'GET' 的情况（假设是 'POST'）
		// 使用提供的 'id' 再次获取客户数据
		if c, err := file.GetDb().GetClient(id); err != nil {
			// 如果获取客户时发生错误，处理错误并返回 Ajax 错误响应
			s.error()
			s.AjaxErr("client ID not found")
			return
		} else {
			// 如果成功获取客户，继续处理
			// 检查 web 用户名字段是否不为空
			if s.getEscapeString("web_username") != "" {
				// 验证 web 用户名是否符合预定义设置和现有用户名
				if s.getEscapeString("web_username") == beego.AppConfig.String("web_username") || !file.GetDb().VerifyUserName(s.getEscapeString("web_username"), c.Id) {
					// 如果用户名重复或无效，返回 Ajax 错误响应
					s.AjaxErr("web login username duplicate, please reset")
					return
				}
			}
			// 检查当前会话是否具有管理员权限
			if s.GetSession("isAdmin").(bool) {
				// 验证 vkey（验证密钥）以确保它不是重复的
				if !file.GetDb().VerifyVkey(s.getEscapeString("vkey"), c.Id) {
					// 如果 vkey 是重复的，返回 Ajax 错误响应
					s.AjaxErr("Vkey duplicate, please reset")
					return
				}
				// 使用请求中的新值更新客户详情
				c.Flow.ExportFlow = int64(s.GetIntNoErr("export_flow")) //设置已使用出口流量
				c.Flow.InletFlow = int64(s.GetIntNoErr("inlet_flow"))   //设置已使用入口流量
				c.Flow.FlowLimit = int64(s.GetIntNoErr("flow_limit"))   // 设置客户端的流量限制
				c.RateLimit = s.GetIntNoErr("rate_limit")               // 设置客户端的速率限制
				c.MaxConn = s.GetIntNoErr("max_conn")                   // 设置客户端的最大连接数
				c.WhiteIpList = RemoveRepeatedElement(strings.Split(s.getEscapeString("whiteiplist"), ":"))
			}
			// 根据配置设置确定用户是否可以更改用户名
			b, err := beego.AppConfig.Bool("allow_user_change_username")
			if s.GetSession("isAdmin").(bool) || (err == nil && b) {
				c.WebUserName = s.getEscapeString("web_username")
			}
			// 如果有现有的速率限制器，停止它
			if c.Rate != nil {
				c.Rate.Stop()
			}
			// 根据速率限制参数设置新的速率限制
			if c.RateLimit > 0 {
				c.Rate = rate.NewRate(int64(c.RateLimit * 1024)) // 将 KB 转换为字节
				c.Rate.Start()                                   // 以新的限制启动速率限制器
			} else {
				c.Rate = rate.NewRate(int64(2 << 23)) // 如果未提供，则使用默认的速率限制
				c.Rate.Start()                        // 以默认限制启动速率限制器
			}
			// 将更新后的客户数据存储回 JSON 文件
			file.GetDb().JsonDb.StoreClientsToJsonFile()
		}
		// 返回成功消息给客户
		s.AjaxOk("save success")
	} else {
		s.AjaxErr("不支持的请求")
	}
}

func RemoveRepeatedElement(arr []string) (newArr []string) {
	newArr = make([]string, 0)
	for i := 0; i < len(arr); i++ {
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if !repeat {
			newArr = append(newArr, arr[i])
		}
	}
	return
}

// 更改状态
func (s *ClientController) ChangeStatus() {
	id := s.GetIntNoErr("id")
	if client, err := file.GetDb().GetClient(id); err == nil {
		client.Status = s.GetBoolNoErr("status")
		if client.Status == false {
			server.DelClientConnect(client.Id)
		}
		s.AjaxOk("modified success")
	}
	s.AjaxErr("modified fail")
}

// 删除客户端
func (s *ClientController) Del() {
	id := s.GetIntNoErr("id")
	if err := file.GetDb().DelClient(id); err != nil {
		s.AjaxErr("delete error")
	}
	server.DelTunnelAndHostByClientId(id, false)
	server.DelClientConnect(id)
	s.AjaxOk("delete success")
}
