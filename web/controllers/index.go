package controllers

import (
	"ehang.io/nps/lib/file"
	"ehang.io/nps/server"
	"ehang.io/nps/server/tool"

	"github.com/astaxie/beego"
)

// IndexController 结构体，负责处理各类页面请求
type IndexController struct {
	BaseController
}

// Index 方法，用于显示仪表盘页面
func (s *IndexController) Index() {
	// 设置网页基础URL
	s.Data["web_base_url"] = beego.AppConfig.String("web_base_url")
	// 获取仪表盘数据
	s.Data["data"] = server.GetDashboardData()
	// 设置页面信息
	s.SetInfo("dashboard")
	// 渲染index/index页面
	s.display("index/index")
}

// Help 方法，用于显示帮助页面
func (s *IndexController) Help() {
	// 设置页面信息
	s.SetInfo("about")
	// 渲染index/help页面
	s.display("index/help")
}

// Tcp 方法，用于显示TCP隧道列表页面
func (s *IndexController) Tcp() {
	s.SetInfo("tcp")
	s.SetType("tcp")
	s.display("index/list")
}

// Udp 方法，用于显示UDP隧道列表页面
func (s *IndexController) Udp() {
	s.SetInfo("udp")
	s.SetType("udp")
	s.display("index/list")
}

// Socks5 方法，用于显示Socks5隧道列表页面
func (s *IndexController) Socks5() {
	s.SetInfo("socks5")
	s.SetType("socks5")
	s.display("index/list")
}

// Http 方法，用于显示HTTP代理隧道列表页面
func (s *IndexController) Http() {
	s.SetInfo("http proxy")
	s.SetType("httpProxy")
	s.display("index/list")
}

// File 方法，用于显示文件服务器页面
func (s *IndexController) File() {
	s.SetInfo("file server")
	s.SetType("file")
	s.display("index/list")
}

// Secret 方法，用于显示秘密隧道列表页面
func (s *IndexController) Secret() {
	s.SetInfo("secret")
	s.SetType("secret")
	s.display("index/list")
}

// P2p 方法，用于显示P2P隧道列表页面
func (s *IndexController) P2p() {
	s.SetInfo("p2p")
	s.SetType("p2p")
	s.display("index/list")
}

// Host 方法，用于显示Host服务器页面
func (s *IndexController) Host() {
	s.SetInfo("host")
	s.SetType("hostServer")
	s.display("index/list")
}

// All 方法，用于显示指定客户端的所有隧道
func (s *IndexController) All() {
	s.Data["menu"] = "client"
	clientId := s.getEscapeString("client_id")
	s.Data["client_id"] = clientId
	s.SetInfo("client id:" + clientId)
	s.display("index/list")
}

// GetTunnel 方法，用于获取隧道列表，带有分页功能
func (s *IndexController) GetTunnel() {
	start, length := s.GetAjaxParams()
	taskType := s.getEscapeString("type")
	clientId := s.GetIntNoErr("client_id")
	// 获取隧道数据和总数
	list, cnt := server.GetTunnel(start, length, taskType, clientId, s.getEscapeString("search"))
	// 返回Ajax表格数据
	s.AjaxTable(list, cnt, cnt, nil)
}

// Add 方法，负责添加新的隧道
func (s *IndexController) Add() {
	if s.Ctx.Request.Method == "GET" {
		// 设置隧道类型和客户端ID，并渲染添加页面
		s.Data["type"] = s.getEscapeString("type")
		s.Data["client_id"] = s.getEscapeString("client_id")
		s.SetInfo("add tunnel")
		s.display()
	} else {
		// 创建新隧道任务
		id := int(file.GetDb().JsonDb.GetTaskId())
		t := &file.Tunnel{
			Port:      s.GetIntNoErr("port"),
			ServerIp:  s.getEscapeString("server_ip"),
			Mode:      s.getEscapeString("type"),
			Target:    &file.Target{TargetStr: s.getEscapeString("target"), LocalProxy: s.GetBoolNoErr("local_proxy")},
			Id:        id,
			Status:    true,
			Remark:    s.getEscapeString("remark"),
			Password:  s.getEscapeString("password"),
			LocalPath: s.getEscapeString("local_path"),
			StripPre:  s.getEscapeString("strip_pre"),
			Flow:      &file.Flow{},
		}

		// 如果端口无效，自动生成端口
		if t.Port <= 0 {
			t.Port = tool.GenerateServerPort(t.Mode)
		}

		// 测试端口是否可用
		if !tool.TestServerPort(t.Port, t.Mode) {
			s.AjaxErr("The port cannot be opened because it may has been occupied or is no longer allowed.")
		}

		// 获取客户端信息
		var err error
		if t.Client, err = file.GetDb().GetClient(s.GetIntNoErr("client_id")); err != nil {
			s.AjaxErr(err.Error())
		}
		// 检查隧道数量是否超限
		if t.Client.MaxTunnelNum != 0 && t.Client.GetTunnelNum() >= t.Client.MaxTunnelNum {
			s.AjaxErr("The number of tunnels exceeds the limit")
		}
		// 创建新任务
		if err := file.GetDb().NewTask(t); err != nil {
			s.AjaxErr(err.Error())
		}
		// 启动任务
		if err := server.AddTask(t); err != nil {
			s.AjaxErr(err.Error())
		} else {
			s.AjaxOkWithId("add success", id, t.Client.VerifyKey)
		}
	}
}

// GetOneTunnel 方法，获取单个隧道信息
func (s *IndexController) GetOneTunnel() {
	id := s.GetIntNoErr("id")
	data := make(map[string]interface{})
	if t, err := file.GetDb().GetTask(id); err != nil {
		data["code"] = 0
	} else {
		data["code"] = 1
		data["data"] = t
	}
	s.Data["json"] = data
	s.ServeJSON()
}

// Edit 方法，负责编辑隧道信息
func (s *IndexController) Edit() {
	id := s.GetIntNoErr("id")
	if s.Ctx.Request.Method == "GET" {
		// 显示编辑页面
		if t, err := file.GetDb().GetTask(id); err != nil {
			s.error()
		} else {
			s.Data["t"] = t
		}
		s.SetInfo("edit tunnel")
		s.display()
	} else {
		// 更新隧道信息
		if t, err := file.GetDb().GetTask(id); err != nil {
			s.error()
		} else {
			if client, err := file.GetDb().GetClient(s.GetIntNoErr("client_id")); err != nil {
				s.AjaxErr("modified error,the client is not exist")
				return
			} else {
				t.Client = client
			}
			// 检查端口并更新
			if s.GetIntNoErr("port") != t.Port {
				t.Port = s.GetIntNoErr("port")
				if t.Port <= 0 {
					t.Port = tool.GenerateServerPort(t.Mode)
				}
				if !tool.TestServerPort(s.GetIntNoErr("port"), t.Mode) {
					s.AjaxErr("The port cannot be opened because it may has been occupied or is no longer allowed.")
					return
				}
			}
			t.ServerIp = s.getEscapeString("server_ip")
			t.Mode = s.getEscapeString("type")
			t.Target = &file.Target{TargetStr: s.getEscapeString("target")}
			t.Password = s.getEscapeString("password")
			t.Id = id
			t.LocalPath = s.getEscapeString("local_path")
			t.StripPre = s.getEscapeString("strip_pre")
			t.Remark = s.getEscapeString("remark")
			t.Target.LocalProxy = s.GetBoolNoErr("local_proxy")
			file.GetDb().UpdateTask(t)
			// 停止并重新启动任务
			server.StopServer(t.Id)
			server.StartTask(t.Id)
		}
		s.AjaxOk("modified success")
	}
}

// Stop 方法，用于停止隧道
func (s *IndexController) Stop() {
	id := s.GetIntNoErr("id")
	if err := server.StopServer(id); err != nil {
		s.AjaxErr("stop error")
	}
	s.AjaxOk("stop success")
}

// Del 方法，用于删除隧道
func (s *IndexController) Del() {
	id := s.GetIntNoErr("id")
	if err := server.DelTask(id); err != nil {
		s.AjaxErr("delete error")
	}
	s.AjaxOk("delete success")
}

// Start 方法，用于启动隧道
func (s *IndexController) Start() {
	id := s.GetIntNoErr("id")
	if err := server.StartTask(id); err != nil {
		s.AjaxErr("start error")
	}
	s.AjaxOk("start success")
}

// HostList 方法，显示主机列表
func (s *IndexController) HostList() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["client_id"] = s.getEscapeString("client_id")
		s.Data["menu"] = "host"
		s.SetInfo("host list")
		s.display("index/hlist")
	} else {
		// 获取主机列表
		start, length := s.GetAjaxParams()
		clientId := s.GetIntNoErr("client_id")
		list, cnt := file.GetDb().GetHost(start, length, clientId, s.getEscapeString("search"))
		s.AjaxTable(list, cnt, cnt, nil)
	}
}

// GetHost 方法，获取单个主机信息
func (s *IndexController) GetHost() {
	if s.Ctx.Request.Method == "POST" {
		data := make(map[string]interface{})
		if h, err := file.GetDb().GetHostById(s.GetIntNoErr("id")); err != nil {
			data["code"] = 0
		} else {
			data["data"] = h
			data["code"] = 1
		}
		s.Data["json"] = data
		s.ServeJSON()
	}
}

// DelHost 方法，删除主机
func (s *IndexController) DelHost() {
	id := s.GetIntNoErr("id")
	if err := file.GetDb().DelHost(id); err != nil {
		s.AjaxErr("delete error")
	}
	s.AjaxOk("delete success")
}

// AddHost 方法，添加新的主机
func (s *IndexController) AddHost() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["client_id"] = s.getEscapeString("client_id")
		s.Data["menu"] = "host"
		s.SetInfo("add host")
		s.display("index/hadd")
	} else {
		id := int(file.GetDb().JsonDb.GetHostId())
		// 创建新主机
		h := &file.Host{
			Id:           id,
			Host:         s.getEscapeString("host"),
			Target:       &file.Target{TargetStr: s.getEscapeString("target"), LocalProxy: s.GetBoolNoErr("local_proxy")},
			HeaderChange: s.getEscapeString("header"),
			HostChange:   s.getEscapeString("hostchange"),
			Remark:       s.getEscapeString("remark"),
			Location:     s.getEscapeString("location"),
			Flow:         &file.Flow{},
			Scheme:       s.getEscapeString("scheme"),
			KeyFilePath:  s.getEscapeString("key_file_path"),
			CertFilePath: s.getEscapeString("cert_file_path"),
			AutoHttps:    s.GetBoolNoErr("AutoHttps"),
		}
		var err error
		// 获取客户端信息
		if h.Client, err = file.GetDb().GetClient(s.GetIntNoErr("client_id")); err != nil {
			s.AjaxErr("add error the client can not be found")
		}
		// 添加新主机
		if err := file.GetDb().NewHost(h); err != nil {
			s.AjaxErr("add fail" + err.Error())
		}
		s.AjaxOkWithId("add success", id, h.Client.VerifyKey)
	}
}

// EditHost 方法，编辑主机信息
func (s *IndexController) EditHost() {
	id := s.GetIntNoErr("id")
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "host"
		// 显示编辑页面
		if h, err := file.GetDb().GetHostById(id); err != nil {
			s.error()
		} else {
			s.Data["h"] = h
		}
		s.SetInfo("edit")
		s.display("index/hedit")
	} else {
		// 更新主机信息
		if h, err := file.GetDb().GetHostById(id); err != nil {
			s.error()
		} else {
			// 检查新主机是否已存在
			if h.Host != s.getEscapeString("host") {
				tmpHost := new(file.Host)
				tmpHost.Host = s.getEscapeString("host")
				tmpHost.Location = s.getEscapeString("location")
				tmpHost.Scheme = s.getEscapeString("scheme")
				if file.GetDb().IsHostExist(tmpHost) {
					s.AjaxErr("host has exist")
					return
				}
			}
			// 更新客户端信息
			if client, err := file.GetDb().GetClient(s.GetIntNoErr("client_id")); err != nil {
				s.AjaxErr("modified error,the client is not exist")
			} else {
				h.Client = client
			}
			h.Host = s.getEscapeString("host")
			h.Target = &file.Target{TargetStr: s.getEscapeString("target")}
			h.HeaderChange = s.getEscapeString("header")
			h.HostChange = s.getEscapeString("hostchange")
			h.Remark = s.getEscapeString("remark")
			h.Location = s.getEscapeString("location")
			h.Scheme = s.getEscapeString("scheme")
			h.KeyFilePath = s.getEscapeString("key_file_path")
			h.CertFilePath = s.getEscapeString("cert_file_path")
			h.Target.LocalProxy = s.GetBoolNoErr("local_proxy")
			h.AutoHttps = s.GetBoolNoErr("AutoHttps")
			file.GetDb().JsonDb.StoreHostToJsonFile()
		}
		s.AjaxOk("modified success")
	}
}
