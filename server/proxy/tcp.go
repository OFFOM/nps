package proxy

import (
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strconv"

	"ehang.io/nps/bridge"
	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/conn"
	"ehang.io/nps/lib/file"
	"ehang.io/nps/server/connection"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
)

// TunnelModeServer 结构体，表示隧道模式服务器
type TunnelModeServer struct {
	BaseServer              // 继承BaseServer结构
	process    process      // 处理函数，用于处理连接
	listener   net.Listener // 监听器，用于监听TCP连接
}

// 创建新的 TunnelModeServer 实例
// 参数：process 处理过程、bridge 网络桥、task 隧道任务配置文件
func NewTunnelModeServer(process process, bridge NetBridge, task *file.Tunnel) *TunnelModeServer {
	s := new(TunnelModeServer)
	s.bridge = bridge   // 绑定网络桥接
	s.process = process // 绑定处理函数
	s.task = task       // 绑定隧道任务配置
	return s
}

// 启动服务器，开始监听并处理TCP连接
func (s *TunnelModeServer) Start() error {
	// 调用 conn.NewTcpListenerAndProcess 创建 TCP 监听并处理连接
	return conn.NewTcpListenerAndProcess(s.task.ServerIp+":"+strconv.Itoa(s.task.Port), func(c net.Conn) {
		// 检查客户端的流量限制和连接数限制
		if err := s.CheckFlowAndConnNum(s.task.Client); err != nil {
			logs.Warn("client id %d, task id %d,error %s, when tcp connection", s.task.Client.Id, s.task.Id, err.Error())
			c.Close() // 关闭连接
			return
		}
		// 记录新连接的日志
		logs.Trace("new tcp connection,local port %d,client %d,remote address %s", s.task.Port, s.task.Client.Id, c.RemoteAddr())
		// 调用处理函数处理新的连接
		s.process(conn.NewConn(c), s)
		// 增加客户端的连接计数
		s.task.Client.AddConn()
	}, &s.listener)
}

// 关闭服务器
func (s *TunnelModeServer) Close() error {
	return s.listener.Close()
}

// WebServer 结构体，表示Web管理方式服务器
type WebServer struct {
	BaseServer // 继承BaseServer结构
}

// 启动Web管理服务器
func (s *WebServer) Start() error {
	// 获取配置的Web管理端口
	p, _ := beego.AppConfig.Int("web_port")
	if p == 0 {
		// 如果端口未配置，则阻塞
		stop := make(chan struct{})
		<-stop
	}
	// 开启Session功能
	beego.BConfig.WebConfig.Session.SessionOn = true
	// 设置静态文件路径
	beego.SetStaticPath(beego.AppConfig.String("web_base_url")+"/static", filepath.Join(common.GetRunPath(), "web", "static"))
	// 设置视图文件路径
	beego.SetViewsPath(filepath.Join(common.GetRunPath(), "web", "views"))

	// 初始化错误变量
	err := errors.New("Web management startup failure ")
	var l net.Listener
	// 获取Web管理监听器
	if l, err = connection.GetWebManagerListener(); err == nil {
		// 初始化Beego HTTP服务
		beego.InitBeforeHTTPRun()
		// 判断是否启用SSL
		if beego.AppConfig.String("web_open_ssl") == "true" {
			// 获取SSL证书和密钥文件路径
			keyPath := beego.AppConfig.String("web_key_file")
			certPath := beego.AppConfig.String("web_cert_file")
			// 启动HTTPS服务
			err = http.ServeTLS(l, beego.BeeApp.Handlers, certPath, keyPath)
		} else {
			// 启动HTTP服务
			err = http.Serve(l, beego.BeeApp.Handlers)
		}
	} else {
		// 记录启动错误日志
		logs.Error(err)
	}
	return err
}

// 关闭Web管理服务器
func (s *WebServer) Close() error {
	return nil
}

// 创建新的Web管理服务器实例
// 参数：bridge 桥接对象
func NewWebServer(bridge *bridge.Bridge) *WebServer {
	s := new(WebServer)
	s.bridge = bridge // 绑定网络桥接
	return s
}

// 定义处理函数类型，用于处理TCP隧道的连接
type process func(c *conn.Conn, s *TunnelModeServer) error

// 处理TCP隧道连接的函数
func ProcessTunnel(c *conn.Conn, s *TunnelModeServer) error {
	// 获取随机目标地址
	targetAddr, err := s.task.Target.GetRandomTarget()
	if err != nil {
		// 处理获取目标地址时的错误
		c.Close() // 关闭连接
		logs.Warn("tcp port %d ,client id %d,task id %d connect error %s", s.task.Port, s.task.Client.Id, s.task.Id, err.Error())
		return err
	}

	// 处理客户端连接，转发到目标地址
	return s.DealClient(c, s.task.Client, targetAddr, nil, common.CONN_TCP, nil, s.task.Client.Flow, s.task.Target.LocalProxy, s.task)
}

// 处理HTTP隧道连接的函数
func ProcessHttp(c *conn.Conn, s *TunnelModeServer) error {
	// 获取请求头中的Host信息
	_, addr, rb, err, r := c.GetHost()
	if err != nil {
		// 如果获取Host失败，关闭连接
		c.Close()
		logs.Info(err)
		return err
	}
	// 处理HTTPS的CONNECT方法，建立隧道连接
	if r.Method == "CONNECT" {
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		rb = nil
	}
	// 进行认证，检查用户名和密码
	if err := s.auth(r, c, s.task.Client.Cnf.U, s.task.Client.Cnf.P); err != nil {
		return err
	}
	// 处理客户端连接，转发到目标地址
	return s.DealClient(c, s.task.Client, addr, rb, common.CONN_TCP, nil, s.task.Client.Flow, s.task.Target.LocalProxy, nil)
}
