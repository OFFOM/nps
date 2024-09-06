package proxy

import (
	"bufio"         // 用于缓冲 I/O
	"crypto/tls"    // 用于 TLS 加密
	"io"            // I/O 操作
	"net"           // 网络操作
	"net/http"      // HTTP 协议操作
	"os"            // 操作系统相关
	"path/filepath" // 文件路径操作
	"strconv"       // 字符串和数字转换
	"strings"       // 字符串处理
	"sync"          // 并发同步操作

	"ehang.io/nps/bridge"            // 引入 nps 桥接器库
	"ehang.io/nps/lib/cache"         // nps 缓存库
	"ehang.io/nps/lib/common"        // 常用工具库
	"ehang.io/nps/lib/conn"          // 连接相关库
	"ehang.io/nps/lib/file"          // 文件操作相关库
	"ehang.io/nps/lib/goroutine"     // 并发相关库
	"ehang.io/nps/server/connection" // 服务器连接库
	"github.com/astaxie/beego/logs"  // 日志库
)

// 定义 httpServer 结构体，用于 HTTP/HTTPS 代理服务器
type httpServer struct {
	BaseServer                 // 嵌入 BaseServer，包含基础的任务和桥接器
	httpPort      int          // HTTP 端口
	httpsPort     int          // HTTPS 端口
	httpServer    *http.Server // HTTP 服务器实例
	httpsServer   *http.Server // HTTPS 服务器实例
	httpsListener net.Listener // HTTPS 监听器，用于监听客户端连接
	useCache      bool         // 是否启用缓存
	addOrigin     bool         // 是否添加源头信息
	cache         *cache.Cache // 缓存实例
	cacheLen      int          // 缓存大小
}

// NewHttp 函数，用于创建 httpServer 实例
func NewHttp(bridge *bridge.Bridge, c *file.Tunnel, httpPort, httpsPort int, useCache bool, cacheLen int, addOrigin bool) *httpServer {
	// 创建一个 httpServer 实例，并初始化字段
	httpServer := &httpServer{
		BaseServer: BaseServer{
			task:   c,            // 设置任务
			bridge: bridge,       // 设置桥接器
			Mutex:  sync.Mutex{}, // 初始化互斥锁
		},
		httpPort:  httpPort,  // HTTP 端口
		httpsPort: httpsPort, // HTTPS 端口
		useCache:  useCache,  // 是否使用缓存
		cacheLen:  cacheLen,  // 缓存大小
		addOrigin: addOrigin, // 是否添加源头信息
	}
	// 如果启用了缓存，则初始化缓存实例
	if useCache {
		httpServer.cache = cache.New(cacheLen) // 创建缓存
	}
	return httpServer // 返回 httpServer 实例
}

// Start 方法启动 HTTP 和 HTTPS 服务
func (s *httpServer) Start() error {
	var err error
	// 读取自定义错误页面内容，如果找不到则默认返回 "nps 404"
	if s.errorContent, err = common.ReadAllFromFile(filepath.Join(common.GetRunPath(), "web", "static", "page", "error.html")); err != nil {
		s.errorContent = []byte("nps 404") // 设置默认错误内容
	}
	// 如果 HTTP 端口有效，启动 HTTP 服务
	if s.httpPort > 0 {
		s.httpServer = s.NewServer(s.httpPort, "http") // 创建 HTTP 服务器
		// 启动 HTTP 服务器
		go func() {
			l, err := connection.GetHttpListener() // 获取 HTTP 监听器
			if err != nil {                        // 如果获取失败，记录错误并退出程序
				logs.Error(err)
				os.Exit(0) // 退出程序
			}
			// 启动 HTTP 服务
			err = s.httpServer.Serve(l) // 使用监听器启动 HTTP 服务器
			if err != nil {             // 如果启动失败，记录错误并退出
				logs.Error(err)
				os.Exit(0) // 退出程序
			}
		}()
	}
	// 如果 HTTPS 端口有效，启动 HTTPS 服务
	if s.httpsPort > 0 {
		s.httpsServer = s.NewServer(s.httpsPort, "https") // 创建 HTTPS 服务器
		// 启动 HTTPS 服务器
		go func() {
			s.httpsListener, err = connection.GetHttpsListener() // 获取 HTTPS 监听器
			if err != nil {                                      // 如果获取失败，记录错误并退出程序
				logs.Error(err)
				os.Exit(0)
			}
			// 启动 HTTPS 服务，错误时记录日志
			logs.Error(NewHttpsServer(s.httpsListener, s.bridge, s.useCache, s.cacheLen).Start())
		}()
	}
	return nil // 返回 nil 表示启动成功
}

// Close 方法关闭 HTTP 和 HTTPS 服务
func (s *httpServer) Close() error {
	// 关闭 HTTPS 监听器（如果存在）
	if s.httpsListener != nil {
		s.httpsListener.Close() // 关闭 HTTPS 监听器
	}
	// 关闭 HTTPS 服务器（如果存在）
	if s.httpsServer != nil {
		s.httpsServer.Close() // 关闭 HTTPS 服务器
	}
	// 关闭 HTTP 服务器（如果存在）
	if s.httpServer != nil {
		s.httpServer.Close() // 关闭 HTTP 服务器
	}
	return nil // 返回 nil 表示关闭成功
}

// handleTunneling 方法处理隧道请求（用于 CONNECT 请求和代理请求）
func (s *httpServer) handleTunneling(w http.ResponseWriter, r *http.Request) {

	var host *file.Host // 用于存储主机信息
	var err error       // 错误信息
	// 根据请求的 Host 获取主机信息
	host, err = file.GetDb().GetInfoByHost(r.Host, r) // 从数据库中获取 Host 信息
	if err != nil {                                   // 如果获取失败，记录日志并返回
		logs.Debug("the url %s %s %s can't be parsed!", r.URL.Scheme, r.Host, r.RequestURI)
		return
	}

	// 如果启用了自动 HTTPS 重定向，并且请求不是 HTTPS，则进行 301 重定向
	if host.AutoHttps && r.TLS == nil {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
		return
	}

	// 如果请求头中有 Upgrade 字段，则认为是 WebSocket 或 HTTP2 请求，使用反向代理
	if r.Header.Get("Upgrade") != "" {
		rProxy := NewHttpReverseProxy(s) // 创建反向代理实例
		rProxy.ServeHTTP(w, r)           // 代理处理请求
	} else {
		// 如果不是 Upgrade 请求，处理标准的 HTTP 请求
		hijacker, ok := w.(http.Hijacker) // 检查响应写入器是否支持 hijacking（劫持）
		if !ok {                          // 如果不支持，返回错误
			http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
			return
		}
		// 劫持 HTTP 连接
		c, _, err := hijacker.Hijack() // 劫持客户端连接
		if err != nil {                // 如果劫持失败，返回错误
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		}
		// 处理被劫持的 HTTP 请求
		s.handleHttp(w, r, conn.NewConn(c)) // 传递 w, r 和 c
	}
}

// handleHttp 方法用于处理 HTTP 请求，建立到目标服务器的隧道连接
func (s *httpServer) handleHttp(w http.ResponseWriter, r *http.Request, c *conn.Conn) {
	var (
		host       *file.Host         // 用于存储主机信息
		target     net.Conn           // 目标服务器的连接
		err        error              // 错误信息
		connClient io.ReadWriteCloser // 客户端连接对象
		scheme     = r.URL.Scheme     // 请求的 URL 协议（http/https）
		lk         *conn.Link         // 链接对象
		targetAddr string             // 目标服务器地址
		lenConn    *conn.LenConn      // 包含连接长度的连接对象
		isReset    bool               // 是否需要重置连接
		wg         sync.WaitGroup     // 用于并发处理的 WaitGroup
		remoteAddr string             // 客户端的远程地址
	)
	// 延迟执行，确保在退出时关闭连接
	defer func() {
		if connClient != nil {
			connClient.Close() // 关闭客户端连接
		} else {
			s.writeConnFail(c.Conn) // 如果客户端连接失败，记录连接失败
		}
		c.Close() // 关闭当前连接
	}()
reset: // 标签用于在需要时重新建立连接
	if isReset {
		host.Client.AddConn() // 如果连接重置，增加客户端连接数
	}

	// 处理 X-Forwarded-For 头部，用于记录客户端的真实 IP
	remoteAddr = strings.TrimSpace(r.Header.Get("X-Forwarded-For")) // 获取客户端的 X-Forwarded-For
	if len(remoteAddr) == 0 {                                       // 如果没有 X-Forwarded-For 头，则使用直接连接的远程地址
		remoteAddr = c.RemoteAddr().String() // 获取远程地址
	}

	// 检查客户端 IP 是否在全局黑名单中
	if IsGlobalBlackIp(c.RemoteAddr().String()) {
		c.Close() // 如果在黑名单中，关闭连接
		return
	}

	// 获取主机信息
	if host, err = file.GetDb().GetInfoByHost(r.Host, r); err != nil { // 从数据库中获取主机信息
		logs.Notice("the url %s %s %s can't be parsed!, host %s, url %s, remote address %s", r.URL.Scheme, r.Host, r.RequestURI, r.Host, r.URL.Path, remoteAddr)
		c.Close() // 如果解析失败，关闭连接
		return
	}

	// 检查客户端流量和连接数限制
	if err := s.CheckFlowAndConnNum(host.Client); err != nil {
		logs.Warn("client id %d, host id %d, error %s, when https connection", host.Client.Id, host.Id, err.Error())
		c.Close() // 如果超出限制，关闭连接
		return
	}
	if !isReset {
		defer host.Client.AddConn() // 如果没有重置，延迟增加客户端连接数
	}
	// 进行身份验证
	if err = s.auth(r, c, host.Client.Cnf.U, host.Client.Cnf.P); err != nil {
		logs.Warn("auth error", err, r.RemoteAddr)
		return
	}
	// 获取目标地址
	if targetAddr, err = host.Target.GetRandomTarget(); err != nil { // 获取随机目标服务器地址
		logs.Warn(err.Error())
		return
	}

	// 检查客户端 IP 是否在该主机的黑名单中
	if common.IsBlackIp(c.RemoteAddr().String(), host.Client.VerifyKey, host.Client.BlackIpList) {
		c.Close() // 如果在黑名单中，关闭连接
		return
	}

	// 检查客户端IP是否在白名单中
	if !common.IsWhiteIp(c.RemoteAddr().String(), host.Client.VerifyKey, host.Client.WhiteIpList) {
		// 使用 http.ResponseWriter 返回 403 错误页面
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden) // 设置 403 Forbidden 状态码

		// 更加美观的中文提示页面
		pageContent := `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>访问被禁止</title>
        <style>
            body {
                font-family: "Arial", sans-serif;
                background-color: #f9f9f9;
                color: #333;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .container {
                background-color: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                max-width: 500px;
                width: 100%;
                text-align: center;
            }
            h1 {
                font-size: 24px;
                color: #e74c3c;
                margin-bottom: 20px;
            }
            p {
                font-size: 18px;
                color: #555;
            }
            .contact {
                margin-top: 20px;
                font-size: 16px;
                color: #888;
            }
            .contact a {
                color: #3498db;
                text-decoration: none;
            }
            .contact a:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>403 禁止访问</h1>
            <p>您的 IP 地址（<strong>` + c.RemoteAddr().String() + `</strong>）未在白名单中。</p>
            <p>如需访问，请联系管理员申请白名单权限。</p>
            <div class="contact">
                <p>联系方式：<a href="mailto:admin@example.com">admin@example.com</a></p>
            </div>
        </div>
    </body>
    </html>
    `

		// 将页面内容写入响应
		w.Write([]byte(pageContent))
		return
	}

	// 建立新的隧道连接
	lk = conn.NewLink("http", targetAddr, host.Client.Cnf.Crypt, host.Client.Cnf.Compress, r.RemoteAddr, host.Target.LocalProxy) // 创建新的链接对象
	if target, err = s.bridge.SendLinkInfo(host.Client.Id, lk, nil); err != nil {                                                // 发送链接信息到目标服务器
		logs.Notice("connect to target %s error %s", lk.Host, err)
		return
	}
	connClient = conn.GetConn(target, lk.Crypt, lk.Compress, host.Client.Rate, true) // 获取客户端连接对象

	// 开启协程从客户端读取数据并转发给目标服务器
	go func() {
		wg.Add(1)                // 增加 WaitGroup 计数
		isReset = false          // 初始化重置标志为 false
		defer connClient.Close() // 延迟关闭客户端连接
		defer func() {
			wg.Done() // 完成后减少计数
			if !isReset {
				c.Close() // 如果没有重置，关闭当前连接
			}
		}()

		// 从客户端读取数据并转发给目标服务器
		err1 := goroutine.CopyBuffer(c, connClient, host.Client.Flow, nil, "") // 复制数据
		if err1 != nil {
			return
		}

		// 读取目标服务器的响应
		resp, err := http.ReadResponse(bufio.NewReader(connClient), r) // 读取响应
		if err != nil || resp == nil || r == nil {
			return
		} else {
			lenConn := conn.NewLenConn(c)               // 包装当前连接
			if err := resp.Write(lenConn); err != nil { // 将响应写回客户端
				logs.Error(err)
				return
			}
		}
	}()

	for {
		// 如果启用了缓存且请求的 URL 在缓存中，则返回缓存的数据
		if s.useCache {
			if v, ok := s.cache.Get(filepath.Join(host.Host, r.URL.Path)); ok { // 从缓存中获取数据
				n, err := c.Write(v.([]byte)) // 将缓存数据写回客户端
				if err != nil {
					break
				}
				logs.Trace("%s request, method %s, host %s, url %s, remote address %s, return cache", r.URL.Scheme, r.Method, r.Host, r.URL.Path, c.RemoteAddr().String())
				host.Client.Flow.Add(int64(n), int64(n)) // 增加流量统计
				// 如果客户端要求关闭连接，则断开连接
				if strings.ToLower(r.Header.Get("Connection")) == "close" || strings.ToLower(r.Header.Get("Connection")) == "" {
					break
				}
				goto readReq // 重新读取请求
			}
		}

		// 修改请求中的 Host 和 Header，并设置代理相关的 Header
		common.ChangeHostAndHeader(r, host.HostChange, host.HeaderChange, c.Conn.RemoteAddr().String())

		logs.Info("%s request, method %s, host %s, url %s, remote address %s, target %s", r.URL.Scheme, r.Method, r.Host, r.URL.Path, remoteAddr, lk.Host)

		// 将请求写入目标服务器
		lenConn = conn.NewLenConn(connClient)    // 包装连接
		if err := r.Write(lenConn); err != nil { // 将请求写入连接
			logs.Error(err)
			break
		}
		host.Client.Flow.Add(int64(lenConn.Len), int64(lenConn.Len)) // 增加流量统计

	readReq: // 标签用于读取新请求
		// 从客户端读取新请求
		r, err = http.ReadRequest(bufio.NewReader(c)) // 读取新的 HTTP 请求
		if err != nil {
			return
		}
		r.URL.Scheme = scheme                                                  // 设置请求的协议
		r.Method = resetReqMethod(r.Method)                                    // 重置请求方法
		if hostTmp, err := file.GetDb().GetInfoByHost(r.Host, r); err != nil { // 获取新的主机信息
			logs.Notice("the url %s %s %s can't be parsed!", r.URL.Scheme, r.Host, r.RequestURI)
			break
		} else if host != hostTmp { // 如果主机发生变化，重置连接
			host = hostTmp
			isReset = true
			connClient.Close() // 关闭客户端连接
			goto reset         // 跳转到重置逻辑
		}
	}
	wg.Wait() // 等待所有并发操作完成
}

// resetReqMethod 函数重置请求方法，处理不完整的 HTTP 请求方法
func resetReqMethod(method string) string {
	// 如果方法为 ET，重置为 GET
	if method == "ET" {
		return "GET"
	}
	// 如果方法为 OST，重置为 POST
	if method == "OST" {
		return "POST"
	}
	return method // 返回原始方法
}

// NewServer 创建一个新的 HTTP/HTTPS 服务器
func (s *httpServer) NewServer(port int, scheme string) *http.Server {
	return &http.Server{
		Addr: ":" + strconv.Itoa(port), // 设置服务器监听的端口
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // 处理器函数
			r.URL.Scheme = scheme   // 设置 URL 的协议
			s.handleTunneling(w, r) // 处理隧道请求
		}),
		// 禁用 HTTP/2 协议
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
}

// NewServerWithTls 创建支持 TLS 的 HTTPS 服务器
func (s *httpServer) NewServerWithTls(port int, scheme string, l net.Listener, certFile string, keyFile string) error {

	if certFile == "" || keyFile == "" { // 如果证书文件为空，记录错误并返回
		logs.Error("证书文件为空")
		return nil
	}
	var certFileByte = []byte(certFile) // 将证书文件转换为字节
	var keyFileByte = []byte(keyFile)   // 将密钥文件转换为字节

	config := &tls.Config{}                          // 创建 TLS 配置
	config.Certificates = make([]tls.Certificate, 1) // 初始化证书数组

	var err error
	// 加载证书和密钥对
	config.Certificates[0], err = tls.X509KeyPair(certFileByte, keyFileByte)
	if err != nil { // 如果加载失败，返回错误
		return err
	}

	// 创建新的 HTTPS 服务器
	s2 := &http.Server{
		Addr: ":" + strconv.Itoa(port), // 设置服务器监听的端口
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // 处理器函数
			r.URL.Scheme = scheme   // 设置 URL 的协议
			s.handleTunneling(w, r) // 处理隧道请求
		}),
		// 禁用 HTTP/2 协议
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig:    config, // 设置 TLS 配置
	}

	return s2.ServeTLS(l, "", "") // 启动 HTTPS 服务器
}
