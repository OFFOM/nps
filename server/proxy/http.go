package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"ehang.io/nps/bridge"
	"ehang.io/nps/lib/cache"
	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/conn"
	"ehang.io/nps/lib/file"
	"ehang.io/nps/lib/goroutine"
	"ehang.io/nps/server/connection"
	"github.com/astaxie/beego/logs"
)

// httpServer 结构体表示一个具有代理功能的HTTP(S)服务器。
type httpServer struct {
	BaseServer
	httpPort      int          // HTTP服务器端口
	httpsPort     int          // HTTPS服务器端口
	httpServer    *http.Server // HTTP服务器实例
	httpsServer   *http.Server // HTTPS服务器实例
	httpsListener net.Listener // HTTPS服务器监听器
	useCache      bool         // 是否启用缓存
	addOrigin     bool         // 是否添加原始Host头
	cache         *cache.Cache // 缓存实例，用于缓存响应
	cacheLen      int          // 缓存大小
}

// NewHttp 初始化一个新的HTTP(S)服务器实例，并根据给定参数进行配置。
func NewHttp(bridge *bridge.Bridge, c *file.Tunnel, httpPort, httpsPort int, useCache bool, cacheLen int, addOrigin bool) *httpServer {
	httpServer := &httpServer{
		BaseServer: BaseServer{
			task:   c,
			bridge: bridge,
			Mutex:  sync.Mutex{},
		},
		httpPort:  httpPort,
		httpsPort: httpsPort,
		useCache:  useCache,
		cacheLen:  cacheLen,
		addOrigin: addOrigin,
	}
	if useCache {
		// 如果启用缓存，则初始化缓存。
		httpServer.cache = cache.New(cacheLen)
	}
	return httpServer
}

// Start 根据配置的端口初始化并启动HTTP和HTTPS服务器。
func (s *httpServer) Start() error {
	var err error
	// 从文件中读取自定义错误页面内容，如果读取失败则使用默认内容。
	if s.errorContent, err = common.ReadAllFromFile(filepath.Join(common.GetRunPath(), "web", "static", "page", "error.html")); err != nil {
		s.errorContent = []byte("nps 404")
	}
	// 如果配置了HTTP端口，则启动HTTP服务器。
	if s.httpPort > 0 {
		s.httpServer = s.NewServer(s.httpPort, "http")
		go func() {
			l, err := connection.GetHttpListener() // 获取HTTP监听器
			if err != nil {
				logs.Error(err)
				os.Exit(0)
			}
			err = s.httpServer.Serve(l) // 启动HTTP服务器
			if err != nil {
				logs.Error(err)
				os.Exit(0)
			}
		}()
	}
	// 如果配置了HTTPS端口，则启动HTTPS服务器。
	if s.httpsPort > 0 {
		s.httpsServer = s.NewServer(s.httpsPort, "https")
		go func() {
			s.httpsListener, err = connection.GetHttpsListener() // 获取HTTPS监听器
			if err != nil {
				logs.Error(err)
				os.Exit(0)
			}
			// 启动HTTPS服务器
			logs.Error(NewHttpsServer(s.httpsListener, s.bridge, s.useCache, s.cacheLen).Start())
		}()
	}
	return nil
}

// Close 关闭HTTP和HTTPS服务器及其监听器。
func (s *httpServer) Close() error {
	if s.httpsListener != nil {
		s.httpsListener.Close()
	}
	if s.httpsServer != nil {
		s.httpsServer.Close()
	}
	if s.httpServer != nil {
		s.httpServer.Close()
	}
	return nil
}

// handleTunneling 处理HTTP隧道请求，例如WebSocket和HTTP CONNECT代理。
func (s *httpServer) handleTunneling(w http.ResponseWriter, r *http.Request) {

	var host *file.Host
	var err error
	host, err = file.GetDb().GetInfoByHost(r.Host, r) // 根据请求的Host获取相关信息
	if err != nil {
		logs.Debug("无法解析URL %s %s %s！", r.URL.Scheme, r.Host, r.RequestURI)
		return
	}

	// 如果设置了自动HTTP到HTTPS的重定向，并且当前请求不是HTTPS，则重定向到HTTPS。
	if host.AutoHttps && r.TLS == nil {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
		return
	}

	// 如果请求头中包含"Upgrade"字段，则表示这是一个WebSocket请求，使用反向代理处理。
	if r.Header.Get("Upgrade") != "" {
		rProxy := NewHttpReverseProxy(s)
		rProxy.ServeHTTP(w, r)
	} else {
		// 否则，进行HTTP劫持。
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "不支持劫持", http.StatusInternalServerError)
			return
		}
		c, _, err := hijacker.Hijack() // 劫持HTTP连接
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		}

		// 处理劫持的HTTP连接
		s.handleHttp(conn.NewConn(c), r)
	}

}

// handleHttp 处理HTTP请求并将其转发到目标服务器。
func (s *httpServer) handleHttp(c *conn.Conn, r *http.Request) {
	var (
		host       *file.Host
		target     net.Conn
		err        error
		connClient io.ReadWriteCloser
		scheme     = r.URL.Scheme
		lk         *conn.Link
		targetAddr string
		lenConn    *conn.LenConn
		isReset    bool
		wg         sync.WaitGroup
		remoteAddr string
	)
	defer func() {
		if connClient != nil {
			connClient.Close()
		} else {
			s.writeConnFail(c.Conn)
		}
		c.Close()
	}()
reset:
	if isReset {
		host.Client.AddConn()
	}

	remoteAddr = strings.TrimSpace(r.Header.Get("X-Forwarded-For")) // 获取请求的远程地址
	if len(remoteAddr) == 0 {
		remoteAddr = c.RemoteAddr().String()
	}

	// 判断访问地址是否在全局黑名单内
	if IsGlobalBlackIp(c.RemoteAddr().String()) {
		c.Close()
		return
	}

	if host, err = file.GetDb().GetInfoByHost(r.Host, r); err != nil {
		logs.Notice("无法解析URL %s %s %s！主机 %s, URL %s, 远程地址 %s", r.URL.Scheme, r.Host, r.RequestURI, r.Host, r.URL.Path, remoteAddr)
		c.Close()
		return
	}

	// 检查流量和连接数限制
	if err := s.CheckFlowAndConnNum(host.Client); err != nil {
		logs.Warn("客户端ID %d, 主机ID %d, 错误 %s, 在HTTPS连接时", host.Client.Id, host.Id, err.Error())
		c.Close()
		return
	}
	if !isReset {
		defer host.Client.AddConn()
	}
	if err = s.auth(r, c, host.Client.Cnf.U, host.Client.Cnf.P); err != nil {
		logs.Warn("认证错误", err, r.RemoteAddr)
		return
	}
	if targetAddr, err = host.Target.GetRandomTarget(); err != nil {
		logs.Warn(err.Error())
		return
	}

	// 判断访问ip是否在黑名单内
	if common.IsBlackIp(c.RemoteAddr().String(), host.Client.VerifyKey, host.Client.BlackIpList) {
		c.Close()
		return
	}

	// 判断访问ip是否在白名单
	if common.IsWhiteIp(c.RemoteAddr().String(), host.Client.VerifyKey, host.Client.BlackIpList) {
		c.Close()
		return
	}

	// 创建连接链接信息
	lk = conn.NewLink("http", targetAddr, host.Client.Cnf.Crypt, host.Client.Cnf.Compress, r.RemoteAddr, host.Target.LocalProxy)
	// 向桥接器发送链接信息
	if target, err = s.bridge.SendLinkInfo(host.Client.Id, lk, nil); err != nil {
		logs.Notice("连接目标 %s 错误 %s", lk.Host, err)
		return
	}
	connClient = conn.GetConn(target, lk.Crypt, lk.Compress, host.Client.Rate, true)

	// 从客户端读取数据
	go func() {
		wg.Add(1)
		isReset = false
		defer connClient.Close()
		defer func() {
			wg.Done()
			if !isReset {
				c.Close()
			}
		}()

		err1 := goroutine.CopyBuffer(c, connClient, host.Client.Flow, nil, "")
		if err1 != nil {
			return
		}

		resp, err := http.ReadResponse(bufio.NewReader(connClient), r)
		if err != nil || resp == nil || r == nil {
			// 如果管道断裂，http响应返回为502错误
			return
		} else {
			lenConn := conn.NewLenConn(c)
			if err := resp.Write(lenConn); err != nil {
				logs.Error(err)
				return
			}
		}
	}()

	for {
		// 如果启用了缓存，并且请求在缓存列表中，则返回缓存
		if s.useCache {
			if v, ok := s.cache.Get(filepath.Join(host.Host, r.URL.Path)); ok {
				n, err := c.Write(v.([]byte))
				if err != nil {
					break
				}
				logs.Trace("%s 请求，方法 %s，主机 %s，URL %s，远程地址 %s，返回缓存", r.URL.Scheme, r.Method, r.Host, r.URL.Path, c.RemoteAddr().String())
				host.Client.Flow.Add(int64(n), int64(n))
				// 如果返回缓存并且未创建与客户端的新连接，连接未设置或关闭，则关闭连接
				if strings.ToLower(r.Header.Get("Connection")) == "close" || strings.ToLower(r.Header.Get("Connection")) == "" {
					break
				}
				goto readReq
			}
		}

		// 修改主机和头信息并设置代理设置
		common.ChangeHostAndHeader(r, host.HostChange, host.HeaderChange, c.Conn.RemoteAddr().String())

		logs.Info("%s 请求，方法 %s，主机 %s，URL %s，远程地址 %s，目标 %s", r.URL.Scheme, r.Method, r.Host, r.URL.Path, remoteAddr, lk.Host)

		// 写入请求
		lenConn = conn.NewLenConn(connClient)
		if err := r.Write(lenConn); err != nil {
			logs.Error(err)
			break
		}
		host.Client.Flow.Add(int64(lenConn.Len), int64(lenConn.Len))

	readReq:
		// 从连接读取请求
		r, err = http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		r.URL.Scheme = scheme
		r.Method = resetReqMethod(r.Method)
		if hostTmp, err := file.GetDb().GetInfoByHost(r.Host, r); err != nil {
			logs.Notice("无法解析URL %s %s %s！", r.URL.Scheme, r.Host, r.RequestURI)
			break
		} else if host != hostTmp {
			host = hostTmp
			isReset = true
			connClient.Close()
			goto reset
		}
	}
	wg.Wait()
}

// resetReqMethod 重置请求方法，如果解析错误则修复它。
func resetReqMethod(method string) string {
	if method == "ET" {
		return "GET"
	}
	if method == "OST" {
		return "POST"
	}
	return method
}

// NewServer 创建一个新的HTTP服务器实例。
func (s *httpServer) NewServer(port int, scheme string) *http.Server {
	return &http.Server{
		Addr: ":" + strconv.Itoa(port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Scheme = scheme
			s.handleTunneling(w, r)
		}),
		// 禁用HTTP/2。
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
}

// NewServerWithTls 创建一个带有TLS证书的HTTPS服务器实例。
func (s *httpServer) NewServerWithTls(port int, scheme string, l net.Listener, certFile string, keyFile string) error {

	if certFile == "" || keyFile == "" {
		logs.Error("证书文件为空")
		return nil
	}
	var certFileByte = []byte(certFile)
	var keyFileByte = []byte(keyFile)

	config := &tls.Config{}
	config.Certificates = make([]tls.Certificate, 1)

	var err error
	config.Certificates[0], err = tls.X509KeyPair(certFileByte, keyFileByte)
	if err != nil {
		return err
	}

	s2 := &http.Server{
		Addr: ":" + strconv.Itoa(port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Scheme = scheme
			s.handleTunneling(w, r)
		}),
		// 禁用HTTP/2。
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig:    config,
	}

	return s2.ServeTLS(l, "", "")
}
