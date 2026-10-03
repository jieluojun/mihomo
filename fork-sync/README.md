支持 cns 入站和出站，写法如下
```yaml
listeners:
  - name: cns-in
    type: cns
    listen: 0.0.0.0
    port: 23333
    key: Meng
    password: 你的加密密码 # 空则不 XOR
    flag: httpUDP
```
```yaml
proxies:
  - name: cns-out
    type: cns
    server: 服务器地址
    port: 23333
    key: Meng # 必须与服务端 Proxy_key 一致；省略时默认为 Meng
    password: 你的加密密码 # 必须与服务端 Encrypt_password 一致；服务端为空时这里也留空
    flag: httpUDP # 必须与服务端 Udp_flag 一致；省略时默认为 httpUDP
    udp: true
    headers:
      Host: baidu.com # 伪装 Host，可按需要修改
```

#############################

支持神秘模块的钉钉直连写法，写法如下
```yaml
proxies:
  - name: 南京电信
    type: http  
    server: 180.101.50.208
    port: 443
    headers:
      With-At: "gw.alicdn.com"
      Host: "153.3.236.22:443"
      X-T5-Auth: "683556433"
      Connection: "Keep-Alive"
```

#############################

支持 TPBox 代理软件的 path 和 del_host 参数支持，写法如下
```yaml
proxies:
  - name: 南京电信
    type: http
    server: 180.101.50.208
    port: 443
    path: @混淆 # 支持停机卡、三爱等混淆免流
    del_host: true # 也可以写成 del-host 删除请求头，存在 Host、User-Agent 等参数时该字段无效
```

路径说明:

假设填写路径为 /path

原版sing-box握手过程

CONNECT /path HTTP/1.1
Host: www.example.com:443
User-Agent: Go-http-client/1.1
Proxy-Connection: Keep-Alive
修改后握手过程
CONNECT www.example.com:443/path HTTP/1.1
Host: www.example.com:443
User-Agent: Go-http-client/1.1
Proxy-Connection: Keep-Alive
-至于有什么用呢?(懂的都懂)

路径填写: @gw.alicdn.com

CONNECT www.example.com:443@gw.alicdn.com HTTP/1.1
Host: www.example.com:443
User-Agent: Go-http-client/1.1
Proxy-Connection: Keep-Alive
请求头说明:

自定义请求头跟原版没有区别

填写格式(一行一条)

Host: www.google.com
User-Agent: okhttp/4.12.0
握手过程
CONNECT www.example.com:443 HTTP/1.1
Host: www.google.com
User-Agent: okhttp/4.12.0
Proxy-Connection: Keep-Alive
Del Host 说明:

开启Del Host后握手时会删除host字段

握手过程

CONNECT www.example.com:443 HTTP/1.1
User-Agent: Go-http-client/1.1
Proxy-Connection: Keep-Alive
至于有什么用呢?

某度直连的http代理在握手时需要添加一个X-T5-Auth头来作为身份验证,开启Del Host后你会发现就算没有添加身份验证 也可以握手成功,其他作用自行探索。

如果添加的自定义请求头中包含Host,Del Host将无效
