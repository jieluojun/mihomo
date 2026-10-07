# 上游 eBPF 更新适配（2026-10-07）

在 `13bc0b8b` 基础上完成此前暂缓项的功能适配。继续使用内置后端，保留本分支的 fake-IP 热更新、TUN 共存、作用域策略及 UDP 在途保活。没有将外部 sing-ebpf 整库替换进来。

## 配置与数据面

- 适配 TanakaLun `2fe3a07f`、`f67d2cb6`：新增 `local.bypass-exclude` 和 `shared.bypass-exclude`。采用独立 LPM 表，不占用 fake-IP 槽；每个作用域每种地址族最多 4096 个归并后的网段。支持多个网段及 IPv4-mapped IPv6 规范化，拒绝无效前缀。
- 覆盖 local cgroup、local TC、shared socket_assign、shared packet_rewrite。命中后优先于可配置的 UID/来源、DNS、端口、私网及规则集绕过。协议开关、自身 socket 和强制安全绕过仍有效。
- fake-IP 更新只修改原有控制记录，不修改强制拦截表。ICMP responder 继续只识别真正的 fake-IP 范围。
- DNS/TUN 共存发布从绕过集合中扣除已启用作用域的强制拦截网段。禁用作用域的配置继续完全忽略；修改 bypass-exclude 列表通过现有配置差异检测重建入站。

```yaml
local:
  enable: true
  data-plane: cgroup
  bypass-private-address: true
  bypass-exclude: [100.64.0.0/10, 'fd7a:115c:a1e0::/48']
```

该配置让相应目标进入 mihomo 规则匹配，并不直接指定某个出站。

## UDP 生命周期

- 适配 sing-ebpf `cb41c483`：增加 token → socket cookie 反向索引，取消恢复路径的全表扫描；保留正向 token 和 peer 的复核，拒绝已失效的反向记录。索引属于单次 backend 生命周期，不跨后端共享。
- 适配 `31b917a5`：可选 ring buffer 发出真实 socket-release 事件；事件队列有界，按当前 UDP 超时清理恢复状态。map/helper/reader 不可用或队列溢出时，定期扫描继续工作，每轮最多处理固定预算。
- 恢复状态采用独立的不可变键 `(socket cookie, release timestamp)`。原 token 表只作为有界 LRU 索引，实际 payload 由事件或扫描按唯一身份删除。这样避免上游按 token 查询、比较、删除之间的内核竞争；失效索引不能复活已删除 payload。
- 适配 `27de53a4` 的 TC 清理目标：为 assignment 增加 generation，用户态仅标记观察到的 generation 失效，不删除内核的当前 assignment。新包重建失效记录，旧清理请求不能影响新 generation；存储由有界 LRU 回收。
- 适配 `088213d2`：日志报告实际 release 路径、ring/deadline 模式和回退原因。现有按增量报告的 datapath 诊断增加 kernel ring 与用户态事件队列丢失计数。
- `5a123442` 的 Android 紧凑容量不直接替换本分支容量策略：本分支 UDP flow 默认 16384、TC assignment 默认 65536、自身 socket 默认 65536，已不低于该更新的值；保留已有显式容量配置。现有 compact self-bypass 常量也已是 16384。
- `c8f7f2ca` 的 socket cookie 单次获取，本分支原已具备，无需重复改动。

## 对象与验证

C 源码和 Go map ABI 一起更新；使用仓库指定的 Android NDK r29 Clang 21 重新生成 bpfel/bpfeb 对象和 manifest。新增策略编译、DNS/TUN 发布、真实内核强制拦截、fake-IP 热更新、真实释放事件、旧事件/新记录隔离、反向索引校验、过期扫描、回退和关闭测试。

已完成的验证：

- `make -C common/ebpf check`：生成对象与 manifest 可复现检查通过。
- `common/ebpf` 的 `with_ebpf,ebpf_integration` 内核测试使用 race 构建运行：144 项顶层测试通过，2 项仅供父测试调用的 helper 单独运行时跳过。
- `common/ebpf`、`listener/sing_ebpf` 的 race 测试，以及 `listener/inbound` 的 EBPF 配置更新 race 测试通过。
- 上述三个包的 `go vet` 通过。
- 使用 `with_gvisor,with_ebpf` 构建 Linux ARM64、Android ARM64 和 Windows AMD64，均通过。

全仓常规回归命令为 `GOMAXPROCS=4 go test -p 2 -parallel 8 -tags with_gvisor,with_ebpf -timeout 15m ./...`。除 `listener/inbound` 外其余包通过；该包的 `TestInboundVMess_TLSMirror_V2RayInterop` 在 watermark、connection enrolment、h2 embedded traffic 子项中出现 `tlsmirror: carrier handshake failed: EOF`。在独立 worktree 的适配前提交 `13bc0b8b` 单独复跑此测试，也在 padding 子项复现相同握手错误；触发子项有波动，说明此握手问题在本次适配前即存在。未将全仓回归标记为通过。

扩展到 `listener/inbound` 全协议互通的 race 测试未通过：检测到 `github.com/metacubex/tls@v0.1.8`、`github.com/metacubex/http@v0.1.8` 的 HTTP/2/TLS 路径并发竞争，随后达到 10 分钟超时；堆栈涉及 `transport/xhttp/server.go`。本次未改动这些协议实现，也未确认基线是否同样触发，因此不将全协议 race 检查标记为通过。

真实 Android/路由器设备不在本机测试范围内；内核执行验证使用 WSL/Linux 的隔离网络和挂载命名空间。
