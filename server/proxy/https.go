package proxy

import (
	"net"
	"net/http"
	"net/url"
	"sync"

	"ehang.io/nps/lib/cache"        // 用于缓存功能
	"ehang.io/nps/lib/common"       // 包含一些常用的实用函数，例如文件读取等
	"ehang.io/nps/lib/conn"         // 处理连接相关的操作
	"ehang.io/nps/lib/crypt"        // 处理加密相关操作，例如 SSL/TLS 的客户端 Hello 消息
	"ehang.io/nps/lib/file"         // 文件操作以及数据库相关的函数
	"github.com/astaxie/beego/logs" // 日志库，用于结构化日志记录
	"github.com/pkg/errors"         // 错误处理库
)

// HttpsServer 是一个 HTTPS 代理服务器的结构体。
// 它嵌入了 httpServer 结构体，并且包含以下成员：
// - listener: 用于接受传入连接的网络监听器
// - httpsListenerMap: 存储不同主机名的 HTTPS 监听器
// - hostIdCertMap: 映射主机 ID 到相应的证书文件
type HttpsServer struct {
	httpServer
	listener         net.Listener
	httpsListenerMap sync.Map
	hostIdCertMap    sync.Map
}

// NewHttpsServer 是 HttpsServer 的构造函数，初始化并返回一个 HttpsServer 实例。
// - l: 监听器，接受传入的网络连接
// - bridge: 用于网络桥接
// - useCache: 是否使用缓存
// - cacheLen: 缓存大小
func NewHttpsServer(l net.Listener, bridge NetBridge, useCache bool, cacheLen int) *HttpsServer {
	https := &HttpsServer{listener: l}
	https.bridge = bridge
	https.useCache = useCache
	if useCache {
		https.cache = cache.New(cacheLen) // 初始化缓存
	}
	return https
}

// Start 启动 HTTPS 服务器，接受连接并处理 HTTPS 请求。
func (https *HttpsServer) Start() error {

	// 监听并接受连接
	conn.Accept(https.listener, func(c net.Conn) {
		serverName, rb := GetServerNameFromClientHello(c) // 从客户端 Hello 消息中获取主机名
		r := buildHttpsRequest(serverName)                // 构建一个 HTTPS 请求对象

		// 从数据库获取主机信息
		if host, err := file.GetDb().GetInfoByHost(serverName, r); err != nil {
			c.Close() // 关闭连接
			logs.Debug("无法解析 URL %s，远程地址 %s", serverName, c.RemoteAddr().String())
			return
		} else {
			// 判断是否使用默认证书还是上传的证书
			if host.CertFilePath == "" || host.KeyFilePath == "" {
				logs.Debug("加载客户端本地证书")
				https.handleHttps2(c, serverName, rb, r) // 处理 HTTPS 请求，使用本地证书
			} else {
				logs.Debug("使用上传证书")
				https.cert(host, c, rb, host.CertFilePath, host.KeyFilePath) // 使用上传的证书
			}
		}
	})

	return nil
}

// cert 处理证书加载逻辑。
// - host: 主机对象
// - c: 网络连接
// - rb: 客户端 Hello 消息的原始字节
// - certFileUrl: 证书文件路径
// - keyFileUrl: 密钥文件路径
func (https *HttpsServer) cert(host *file.Host, c net.Conn, rb []byte, certFileUrl string, keyFileUrl string) {
	var l *HttpsListener
	i := 0

	// 遍历 hostIdCertMap 并检查是否有已删除的主机，释放其相关的监听器
	https.hostIdCertMap.Range(func(key, value interface{}) bool {
		i++
		// 如果 host Id 不存在，则从 map 中删除
		if id, ok := key.(int); ok {
			var err error
			_, err = file.GetDb().GetHostById(id)
			if err != nil {
				// 如果 host 已经不存在，释放 Listener
				logs.Error(err)
				if oldL, ok := https.httpsListenerMap.Load(value); ok {
					err := oldL.(*HttpsListener).Close() // 关闭旧的监听器
					if err != nil {
						logs.Error(err)
					}
					https.httpsListenerMap.Delete(value) // 从监听器 map 中删除
					https.hostIdCertMap.Delete(key)      // 从证书 map 中删除
					logs.Info("Listener 已释放")
				}
			}
		}
		return true
	})

	logs.Info("当前 Listener 连接数量", i)

	// 如果 host 的证书已经存在于 hostIdCertMap 中
	if cert, ok := https.hostIdCertMap.Load(host.Id); ok {
		if cert == certFileUrl {
			// 证书未变动，直接加载对应的监听器
			if v, ok := https.httpsListenerMap.Load(certFileUrl); ok {
				l = v.(*HttpsListener)
			}
		} else {
			// 证书有变化，重新加载新证书
			l = NewHttpsListener(https.listener)
			https.NewHttps(l, certFileUrl, keyFileUrl)
			// 关闭旧的监听器
			if oldL, ok := https.httpsListenerMap.Load(cert); ok {
				err := oldL.(*HttpsListener).Close()
				if err != nil {
					logs.Error(err)
				}
				https.httpsListenerMap.Delete(cert)
			}
			// 更新监听器和证书映射
			https.httpsListenerMap.Store(certFileUrl, l)
			https.hostIdCertMap.Store(host.Id, certFileUrl)
		}
	} else {
		// 第一次加载证书
		l = NewHttpsListener(https.listener)
		https.NewHttps(l, certFileUrl, keyFileUrl)
		https.httpsListenerMap.Store(certFileUrl, l)
		https.hostIdCertMap.Store(host.Id, certFileUrl)
	}

	// 接受连接并处理
	acceptConn := conn.NewConn(c)
	acceptConn.Rb = rb
	l.acceptConn <- acceptConn
}

// handleHttps2 处理 HTTPS 代理，直接代理到其他客户端。
// - c: 网络连接
// - hostName: 主机名
// - rb: 客户端 Hello 消息的原始字节
// - r: HTTPS 请求对象
func (https *HttpsServer) handleHttps2(c net.Conn, hostName string, rb []byte, r *http.Request) {
	var targetAddr string
	var host *file.Host
	var err error

	// 从数据库中获取主机信息
	if host, err = file.GetDb().GetInfoByHost(hostName, r); err != nil {
		c.Close() // 无法解析主机名，关闭连接
		logs.Debug("无法解析 URL %s", hostName)
		return
	}

	// 检查连接流量和数量是否超限
	if err := https.CheckFlowAndConnNum(host.Client); err != nil {
		logs.Debug("客户端 ID %d，主机 ID %d，HTTPS 连接时发生错误: %s", host.Client.Id, host.Id, err.Error())
		c.Close()
		return
	}
	defer host.Client.AddConn()

	// 身份认证
	if err = https.auth(r, conn.NewConn(c), host.Client.Cnf.U, host.Client.Cnf.P); err != nil {
		logs.Warn("认证错误", err, r.RemoteAddr)
		return
	}

	// 获取目标地址
	if targetAddr, err = host.Target.GetRandomTarget(); err != nil {
		logs.Warn(err.Error())
	}

	// 处理客户端连接
	logs.Info("新的 HTTPS 连接，客户端 ID %d，主机 %s，远程地址 %s", host.Client.Id, r.Host, c.RemoteAddr().String())
	https.DealClient(conn.NewConn(c), host.Client, targetAddr, rb, common.CONN_TCP, nil, host.Client.Flow, host.Target.LocalProxy, nil)
}

// Close 关闭 HTTPS 服务器的监听器
func (https *HttpsServer) Close() error {
	return https.listener.Close()
}

// NewHttps 用证书和密钥文件启动新的 HTTPS 服务器。
// - l: 网络监听器
// - certFile: 证书文件
// - keyFile: 密钥文件
func (https *HttpsServer) NewHttps(l net.Listener, certFile string, keyFile string) {
	go func() {
		logs.Error(https.NewServerWithTls(0, "https", l, certFile, keyFile)) // 启动 HTTPS 服务
	}()
}

// handleHttps 处理 HTTPS 连接。
// - c: 网络连接
func (https *HttpsServer) handleHttps(c net.Conn) {
	hostName, rb := GetServerNameFromClientHello(c) // 从客户端 Hello 消息中获取主机名
	var targetAddr string
	r := buildHttpsRequest(hostName) // 构建 HTTPS 请求对象
	var host *file.Host
	var err error

	// 从数据库获取主机信息
	if host, err = file.GetDb().GetInfoByHost(hostName, r); err != nil {
		c.Close() // 无法解析主机名，关闭连接
		logs.Notice("无法解析 URL %s", hostName)
		return
	}

	// 检查连接流量和数量限制
	if err := https.CheckFlowAndConnNum(host.Client); err != nil {
		logs.Warn("客户端 ID %d，主机 ID %d，HTTPS 连接时发生错误: %s", host.Client.Id, host.Id, err.Error())
		c.Close()
		return
	}
	defer host.Client.AddConn()

	// 认证
	if err = https.auth(r, conn.NewConn(c), host.Client.Cnf.U, host.Client.Cnf.P); err != nil {
		logs.Warn("认证错误", err, r.RemoteAddr)
		return
	}

	// 获取目标地址
	if targetAddr, err = host.Target.GetRandomTarget(); err != nil {
		logs.Warn(err.Error())
	}

	// 处理客户端连接
	logs.Trace("新的 HTTPS 连接，客户端 ID %d，主机 %s，远程地址 %s", host.Client.Id, r.Host, c.RemoteAddr().String())
	https.DealClient(conn.NewConn(c), host.Client, targetAddr, rb, common.CONN_TCP, nil, host.Client.Flow, host.Target.LocalProxy, nil)
}

// HttpsListener 结构体用于管理 HTTPS 监听器。
// - acceptConn: 一个通道，接受传入的连接
// - parentListener: 父监听器，实际的网络监听器
type HttpsListener struct {
	acceptConn     chan *conn.Conn
	parentListener net.Listener
}

// NewHttpsListener 创建一个新的 HttpsListener。
// - l: 网络监听器
func NewHttpsListener(l net.Listener) *HttpsListener {
	return &HttpsListener{parentListener: l, acceptConn: make(chan *conn.Conn)}
}

// Accept 等待并接受连接。
func (httpsListener *HttpsListener) Accept() (net.Conn, error) {
	httpsConn := <-httpsListener.acceptConn
	if httpsConn == nil {
		return nil, errors.New("获取连接错误")
	}
	return httpsConn, nil
}

// Close 关闭 HTTPS 监听器。
func (httpsListener *HttpsListener) Close() error {
	return nil
}

// Addr 返回监听器的地址。
func (httpsListener *HttpsListener) Addr() net.Addr {
	return httpsListener.parentListener.Addr()
}

// GetServerNameFromClientHello 从客户端的 Hello 消息中获取服务器名称。
// - c: 网络连接
func GetServerNameFromClientHello(c net.Conn) (string, []byte) {
	buf := make([]byte, 4096)  // 缓存数据
	data := make([]byte, 4096) // 存储实际读取的数据
	n, err := c.Read(buf)
	if err != nil {
		return "", nil
	}
	if n < 42 {
		return "", nil
	}
	copy(data, buf[:n])
	clientHello := new(crypt.ClientHelloMsg) // 创建 ClientHello 消息对象
	clientHello.Unmarshal(data[5:n])         // 反序列化数据，解析 ClientHello 消息
	return clientHello.GetServerName(), buf[:n]
}

// buildHttpsRequest 构建一个 HTTPS 请求对象。
// - hostName: 主机名
func buildHttpsRequest(hostName string) *http.Request {
	r := new(http.Request) // 创建请求对象
	r.RequestURI = "/"     // 设置请求 URI
	r.URL = new(url.URL)   // 创建 URL 对象
	r.URL.Scheme = "https" // 设置 URL 的协议为 HTTPS
	r.Host = hostName      // 设置主机名
	return r
}
