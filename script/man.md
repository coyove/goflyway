# 通用命令

## -h / -help
显示简单/详细帮助信息

## -c path__to__file
从文件加载配置，配置文件一般为ini格式。
在使用`-help`输出帮助时，一个命令前如果有方括号括起的属性，则代表其可以写入配置文件中，如`-lv`的帮助如下：
```
[loglevel] Logging level: {dbg0, dbg, log, info, warn, err, off}
    ^~~
```
则命令行命令`-lv dbg`等效于在配置文件中写入：
```
loglevel=dbg
```

### gofw.conf
在不指定配置文件的情况下，goflyway会尝试寻找并加载用户目录（`~`或`%USERPROFILE%`）下的`gofw.conf`文件。

### -y config_section
一个配置文件中可以包涵多个配置，如：
```
[config1]
upstream=server1
[config2]
upstream=server2
```
用命令`-y config2`连接`server2`。该命令必须与`-c`一起使用，若不指定`-y`，加载的配置文件也不会生效。

## -lv level
日志输出层级，`level`可为：

* dbg0
* dbg
* log
* info
* warn
* err
* off（关闭输出）

更高级的用法请参见[logg](https://github.com/coyove/common/tree/master/logg)。

## -k password
设置密码，服务端与客户端需保持一致。

## -l address
设置监听地址。
对于服务端来说，该地址是客户端需要连接的地址；
对于客户端来说，该地址是本地HTTP/SOCKS5代理服务器绑定的地址。

## -t seconds
空闲TCP连接自动断开时间，单位为秒，默认`20`，即没有数据传输20秒后连接关闭。设为0则表示永远不会自动关闭。

## -U protocol
设置底层连接协议。`protocol`可以为：

* kcp
* http（默认）
* https

**该命令必须同时在客户端和服务端启用并保持一致**

## -gen-ca
生成一对新的`ca.pem`和`key.pem`。生成完成后请不要变更它们的名字，也不要移动文件位置。

## -acl path__to__acl
加载ACL文件。

ACL是shadowsocks使用的一种访问控制规则设置。同时goflyway也支持简单的白名单列表（即一行一个域名，表示直连）。

goflyway默认加载的是同目录下的`chinalist.txt`白名单列表，如果找不到则会通过地理IP来判断：对于中国大陆IP一律直连。

对于服务端来说，ACL文件用于控制代理黑名单，即对于`[outbound_block_list]`内的域名或IP，服务端都将拒绝代理。

## -acl-cache size
ACL规则的缓存大小。

# 服务端命令

## -throt bytes
限速，单位字节每秒。该命令针对所有的客户端连接。

## -throt-max bytes
限流辅助设置参数，请至少设置为`-throt`值的16倍。

## -disable-udp
拒绝所有客户端UDP中继的请求。

## -disable-localrp
拒绝所有客户端Remote Port Forwarding请求。

## -proxy-pass address
对于无效的客户端请求，将其转发至`address`：
`address`可以是一个HTTP服务，也可以是本地的一个路径。如果启用前者，goflyway相当于一个反向代理；如果启用后者，goflyway相当于一个静态文件服务器。

## -lbind-timeout seconds
设置Remote Port Forwarding请求的超时时间，单位秒。

### -lbind-cap
Remote Port Forwarding的辅助参数。

## -autocert www.example.com
使用`Let’s Encrypt`获得证书，使用该命令则goflyway会默认打开`-U https`且监听80和443端口。请确保域名指向了服务端所在IP。

# 客户端命令

## -g
全局代理。

## -up address
服务端地址。`address`可以有以下几种格式：

* `gfw://1.2.3.4:8100` 直连服务端，`gfw://`可以省略
* `ws://1.2.3.4:8100` 使用WebSocket协议连接服务端
* `cf://www.example.com:80` 连接托管在Cloudflare上的`www.example.com`
* `cfs://www.example.com:80` 使用HTTPS连接托管在Cloudflare上的`www.example.com`
* `http://1.2.3.4:8100` 客户端启用中间人模式，使用该模式前先使用`-gen-ca`生成证书，并将生成的`ca.pem`加入至系统信任证书列表中
* `https://5.6.7.8:3000/1.2.3.4:8100` 使用HTTPS代理（5.6.7.8:3000）连接服务端
* `http://5.6.7.8:3000/1.2.3.4:8100` 使用HTTP代理（5.6.7.8:3000）连接服务端，客户端启用中间人

## -a username:password
当客户端的代理类型为`HTTP Proxy`时，其他程序需要使用认证`username:password`才可以连接客户端。（请注意之间的冒号）

## -cipher mode
设置加密模式，`mode`可以为：

* full
* partial
* none

除非使用`-U https`，否则请不要使用`none`。

## -udp-tcp num
使用`UDP over TCP`时，该命令设置了对于同一个UDP目标地址，goflyway使用`num`条TCP连接进行承载。`num`默认为1。

## -web-port port
Web控制台监听的端口号，默认为`65536`，代表控制台端口为`客户端HTTP/SCOKS5代理的端口号+10`。设为`0`禁用控制台，设为其他有效值，则端口号与其相符。

## -mux
设置TCP混流最大连接数，默认0，代表禁用。

## -mitm-dump path__to__file
在启用中间人模式后，使用该命令对所有的HTTP请求和响应进行转储。

## -bind address
启用Local Port Forwarding。

## -lbind address
启用Remote Port Forwarding。

### -lbind-conns
Remote Port Forwarding相关设置参数。

# CURL命令

## -get URL
发起`GET`请求。

## -post URL
发起`POST`请求。

## -put URL
发起`PUT`请求。

## -delete URL
发起`DELETE`请求。

## -options URL
发起`OPTIONS`请求。

## -trace URL
发起`TRACE`请求。

## -patch URL
发起`PATCH`请求。

## -F string
设置请求表单，如：
```
-F "a=1&b=2"
-F "a=1&b=@path_to_file"
```

## -H string
设置请求HTTP头，如：
```
-F "X-Header: abc\r\nX-Header2: 123"
```

## -C string
设置请求的Cookies。

## -M
设置请求的`Content-Type`为`multipart`。

## -pj
假定返回的内容为JSON并对其格式化输出。

## 以下命令为 Android 兼容命令，请不要使用：
* -u 
* -m 
* -b 
* -V 
* -fast-open
* -vpn
