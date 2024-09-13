package proxy

import (
	"errors"
	"net"
	"net/http"
	"sort"
	"sync"

	"ehang.io/nps/bridge"
	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/conn"
	"ehang.io/nps/lib/file"
	"github.com/astaxie/beego/logs"
)

// Service 接口定义了启动和关闭服务的基本方法
type Service interface {
	Start() error // 启动服务
	Close() error // 关闭服务
}

// NetBridge 接口定义了如何向远程客户端发送链接信息
type NetBridge interface {
	SendLinkInfo(clientId int, link *conn.Link, t *file.Tunnel) (target net.Conn, err error)
}

// BaseServer 结构体定义了一个基础服务器，包含如ID、bridge接口和任务等属性
// sync.Mutex 用于在多个协程之间提供同步
type BaseServer struct {
	id           int          // 服务器ID
	bridge       NetBridge    // 用于与bridge交互的接口
	task         *file.Tunnel // 指向Tunnel对象的引用，定义了该服务器的任务
	errorContent []byte       // 连接失败时写入的错误内容
	sync.Mutex                // 嵌入的互斥锁，用于流操作的线程安全
}

// NewBaseServer 是一个构造函数，用于创建BaseServer实例
// 它接受一个bridge和一个task，并将它们初始化到返回的BaseServer对象中
func NewBaseServer(bridge *bridge.Bridge, task *file.Tunnel) *BaseServer {
	return &BaseServer{
		bridge:       bridge,
		task:         task,
		errorContent: nil,
		Mutex:        sync.Mutex{},
	}
}

// FlowAdd 方法添加流量（进出流量）到当前任务的流量统计中
// 由于使用了互斥锁，该方法是线程安全的
func (s *BaseServer) FlowAdd(in, out int64) {
	s.Lock()                      // 锁定互斥锁以确保线程安全
	defer s.Unlock()              // 完成操作后解锁
	s.task.Flow.ExportFlow += out // 增加出站流量
	s.task.Flow.InletFlow += in   // 增加入站流量
}

// FlowAddHost 方法为特定主机添加流量（进出流量）到它的流量统计中
// 该方法同样是线程安全的
func (s *BaseServer) FlowAddHost(host *file.Host, in, out int64) {
	s.Lock()                    // 锁定互斥锁以确保线程安全
	defer s.Unlock()            // 完成操作后解锁
	host.Flow.ExportFlow += out // 增加主机的出站流量
	host.Flow.InletFlow += in   // 增加主机的入站流量
}

// writeConnFail 方法在连接失败时将错误信息发送给客户端
// 它会写入预定义的错误信息和附加的错误内容
func (s *BaseServer) writeConnFail(c net.Conn) {
	c.Write([]byte(common.ConnectionFailBytes)) // 写入预定义的连接失败信息
	c.Write(s.errorContent)                     // 写入具体的错误内容
}

// auth 方法检查客户端请求的身份验证信息（用户名和密码）是否正确
// 如果验证失败，会返回401 Unauthorized，并关闭连接
func (s *BaseServer) auth(r *http.Request, c *conn.Conn, u, p string) error {
	if u != "" && p != "" && !common.CheckAuth(r, u, p) { // 如果用户名和密码不为空，且验证失败
		c.Write([]byte(common.UnauthorizedBytes)) // 写入401 Unauthorized信息
		c.Close()                                 // 关闭连接
		return errors.New("401 Unauthorized")     // 返回未经授权的错误
	}
	return nil // 验证成功
}

// CheckFlowAndConnNum 方法检查客户端是否超出了流量或连接数限制
// 如果超出限制，返回相应的错误信息
func (s *BaseServer) CheckFlowAndConnNum(client *file.Client) error {
	// 检查流量限制
	if client.Flow.FlowLimit > 0 && (client.Flow.FlowLimit<<20) < (client.Flow.ExportFlow+client.Flow.InletFlow) {
		// 如果客户端的流量超出限制，返回错误信息
		return errors.New("Traffic exceeded")
	}
	// 检查连接数限制
	if !client.GetConn() {
		// 如果客户端的连接数超出限制，返回错误信息
		return errors.New("Connections exceed the current client limit")
	}
	return nil // 客户端没有超出限制
}

// in 方法检查目标字符串是否存在于一个已排序的字符串数组中
// 它使用二分查找来高效地找到目标
func in(target string, str_array []string) bool {
	sort.Strings(str_array)                        // 对数组进行排序以便二分查找
	index := sort.SearchStrings(str_array, target) // 使用二分查找寻找目标字符串
	if index < len(str_array) && str_array[index] == target {
		// 如果找到目标字符串，返回true
		return true
	}
	return false // 如果没有找到目标字符串，返回false
}

// DealClient 方法处理新的客户端连接，包括黑名单检查以及数据传输的启动
// 它还负责通过bridge发送链接信息并设置连接
func (s *BaseServer) DealClient(c *conn.Conn, client *file.Client, addr string,
	rb []byte, tp string, f func(), flow *file.Flow, localProxy bool, task *file.Tunnel) error {

	// 检查客户端IP是否在全局黑名单中
	if IsGlobalBlackIp(c.RemoteAddr().String()) {
		c.Close() // 如果IP在黑名单中，关闭连接
		return nil
	}

	// 检查客户端IP是否在客户端的黑名单中
	if common.IsBlackIp(c.RemoteAddr().String(), client.VerifyKey, client.BlackIpList) {
		// 构建一个HTTP响应，返回一个简单的页面
		httpResponse := "HTTP/1.1 403 Forbidden\r\n" + // 返回403 Forbidden状态码
			"Content-Type: text/html\r\n" +
			"Connection: close\r\n\r\n" + // 响应头结束
			"<html><body><h1>403 Forbidden</h1><p>ip在黑名单中.</p></body></html>"

		// 将HTTP响应写入连接
		c.Write([]byte(httpResponse))

		c.Close() // 发送响应后关闭连接
		return nil
	}

	// 判断是否开启白名单
	if client.WhiteIpis == "1" {
		// 判断访问ip是否在白名单内
		isWhite, ip, vkey := common.IsWhiteIp(c.RemoteAddr().String(), client.VerifyKey, client.WhiteIpList)
		if !isWhite {
			// 定义一个美观的提示页面
			htmlContent := `
	<!DOCTYPE html>
	<html lang="zh-CN">
	
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>访问限制</title>
		<style>
			* {
				margin: 0;
				padding: 0;
				box-sizing: border-box;
			}
	
			body {
				font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
				background-color: #f0f2f5;
				color: #333;
				display: flex;
				justify-content: center;
				align-items: center;
				height: 100vh;
				margin: 0;
			}
	
			.container {
				background-color: #ffffff;
				padding: 40px 30px;
				border-radius: 12px;
				box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
				max-width: 400px;
				text-align: center;
				animation: fadeIn 0.5s ease;
			}
	
			@keyframes fadeIn {
				from {
					opacity: 0;
					transform: scale(0.95);
				}
	
				to {
					opacity: 1;
					transform: scale(1);
				}
			}
	
			h1 {
				font-size: 24px;
				color: #ff4b5c;
				margin-bottom: 20px;
			}
	
			p {
				font-size: 16px;
				margin-bottom: 20px;
				color: #666;
			}
	
			.highlight {
				color: #ff4b5c;
				font-weight: bold;
			}
	
			.form-group {
				margin-bottom: 20px;
			}
	
			.input {
				padding: 12px;
				width: 100%;
				font-size: 16px;
				border: 1px solid #ccc;
				border-radius: 8px;
				transition: border-color 0.3s ease;
			}
	
			.btn {
				display: inline-block;
				width: 100%;
				padding: 12px;
				color: #fff;
				background-color: #007bff;
				border: none;
				border-radius: 8px;
				font-size: 16px;
				cursor: pointer;
				transition: background-color 0.3s ease;
			}
	
			.btn:hover {
				background-color: #0056b3;
			}
		</style>
		<script>
			function submitPassword() {
				// 获取输入框的密码和 vkey
				const password = document.getElementById('password').value;
				const vkey = document.getElementById('vkey').value;
				const ip = document.getElementById('ip').value;
	
				// 发送异步请求到服务器
				fetch('http://www.vccu.cn:56000/auip', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json'
					},
					// 将 password 和 vkey 一起发送到服务器
					body: JSON.stringify({ password: password, vkey: vkey ,ip: ip})
				})
					.then(response => {
						// 检查响应的状态码，如果不成功则抛出错误
						if (!response.ok) {
							throw new Error('服务器返回了一个错误状态: ' + response.status);
						}
						return response.json(); // 将响应转换为 JSON
					})
					.then(data => {
						// 根据返回的 success 和 message 显示提示信息
						if (data.success) {
							alert(data.message);
							// location.reload(); // 刷新页面
						} else {
							alert(data.message); // 显示服务器返回的 message
						}
					})
					.catch(error => {
						// 捕获网络错误或服务器返回的异常错误
						console.error('请求出错:', error);
						alert('请求出错，请稍后再试: ' + error.message);
					});
			}
		</script>
	</head>
	
	<body>
	<div class="container">
		<h1>访问受限</h1>
		<p>您的IP地址<span class="highlight">(` + ip + `)</span>不在白名单内，请输入访问密码。</p>
		<div class="form-group">
			<input type="text" name="password" id="password" placeholder="请输入密码" class="input"  required>
			<input type="hidden" name="vkey" id="vkey" value="` + vkey + `">
			<input type="hidden" name="ip" id="ip" value="` + ip + `">
		</div>
		<button class="btn" onclick="submitPassword()">确认提交</button>
	</div>
	</body>
	</html>
		`
			c.Write([]byte(htmlContent))
			c.Close()
			return nil
		}
	}

	// 创建一个新的Link对象，表示到目标地址的连接
	link := conn.NewLink(tp, addr, client.Cnf.Crypt, client.Cnf.Compress, c.Conn.RemoteAddr().String(), localProxy)
	if target, err := s.bridge.SendLinkInfo(client.Id, link, s.task); err != nil {
		// 如果通过bridge发送链接信息时出错，记录错误并关闭连接
		logs.Warn("get connection from client id %d  error %s", client.Id, err.Error())
		c.Close()  // 关闭连接
		return err // 返回错误信息
	} else {
		if f != nil {
			f() // 如果存在回调函数，执行该回调
		}
		// 开始在目标和客户端之间复制数据，包含加密、压缩和流量控制
		conn.CopyWaitGroup(target, c.Conn, link.Crypt, link.Compress, client.Rate, flow, true, rb, task)
	}
	return nil
}

// IsGlobalBlackIp 检查目标地址是否在全局黑名单中
func IsGlobalBlackIp(ipPort string) bool {
	// 获取全局黑名单列表
	global := file.GetDb().GetGlobal()
	if global != nil {
		// 获取客户端的IP地址
		ip := common.GetIpByAddr(ipPort)
		// 检查IP是否在全局黑名单中
		if in(ip, global.BlackIpList) {
			logs.Error("IP地址[" + ip + "]在全局黑名单列表内")
			return true
		}
	}
	return false // IP不在全局黑名单中
}
