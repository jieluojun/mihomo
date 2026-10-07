# 上游同步记录（2026-10-07）

本次以 `f4b83992` 为起点。完整合并 `vernesong/Alpha` 的 `c3b2cb5f`，包含
`MetaCubeX/Alpha` 的 `9f053c49`；eBPF 按功能移植，继续使用内置后端。
没有将 TanakaLun 的整条分支标记为已合并，也没有切换到外部 sing-ebpf 依赖。

## 已合入

- WireGuard 设备及协议栈延迟初始化，更新配套 sing-wireguard 依赖。
- Smart TCP/UDP 传输中错误回报、TCPStats 解包循环保护、首次写入包装器的幂等关闭。
  错误回报接入本分支的有界统计队列；补上只有写入失败时的统计。
  保留本分支的封禁恢复、探测目标和 TTL 规则，以及只关闭停滞连接的行为。
- cgroup 绕过规则动态更新同时刷新 IPv4/IPv6 控制标志；控制写入失败时恢复原表和标志。
  对应 sing-ebpf `9ab5bf8c`。本后端的静态私网绕过由独立标志处理，不需要新库的
  “静态与动态 pass 集合求并集”适配。
- cgroup 旧内核不支持原子 lookup-and-delete 时保留 LRU 表项，避免 lookup 后删除
  覆盖了并发内核更新。对应 `b412b3db`。
- 识别旧 `sing_ebpf_` 程序名称并回收旧挂载；冲突错误指出现有 owner。
  对应 `9f2e0282`、`0d49f66e`。
- Android netd hook 接管只接受可验证的直通程序，保留原挂载模式并在关闭时恢复；
  失败恢复保留资源供重试。BPF_PROG_QUERY 使用完整的 64 字节属性布局。
  对应 `a0edc850`。进程跟踪、自身绕过等可选挂载不能接管或回收正在运行的入站 hook。
- 支持用户态注册 socket cookie 配合独立 socket-release hook 清理；挂载失败保留
  LRU 回退。对应 `659b6f23`。保留现有 map 容量。
- 禁用 local/shared 配置块均完全忽略，包括无效旧选项、Android 包名和规则集名称；
  运行中规则集更新遵循同样规则。对应 TanakaLun `ef6440c1`。
- 多个 eBPF 入站各自注册 socket 保护回调，关闭只注销自身，所有活跃入站都能登记
  新 socket。适配 TanakaLun `0db2d7a5`，并修正其“单槽回调加引用计数”仍无法保护
  全部入站的问题；注销函数幂等，旧注销句柄不影响之后的新注册。

## 已有对应实现或不适用

- TanakaLun `96f7edf7` 的 local/shared DNS 区分，本分支 `a729ade7` 已实现，
  还覆盖同一 TC listener 上的 shared socket_assign 流量。
- `0db2d7a5` 的 UDP 空闲回收、reply socket 扫描和 TC 清理，本分支已有有界分片
  扫描、在途任务保活与 retired attachment 重试；`5a912c35` 的空表后不唤醒问题
  不适用于本分支的周期 janitor。
- `155ade76` 的超时下限继续使用本分支已有的默认 300 秒、最小 5 秒夹取行为。
- `802c69fa` 修复的是新 ActionPolicy 在 Prepare 时直接填充静态目的表的缓存；
  本后端在 `UpdateCompiledBypassCIDR` 中统一填表并记录缓存。
- `ce09a082` 修复的新 ActionPolicy 端口判定路径，本后端没有；DNS 控制模式与 UID
  策略独立编译。
- TanakaLun 的主上游同步提交已由 Smart 分支的合并覆盖；其依赖版本更新不用原样
  带入内置后端。

## 本次暂缓

- `bypass-exclude`（TanakaLun `2fe3a07f`、`f67d2cb6`）：外部后端使用与 fake-IP
  共用的强制拦截槽，本分支具有 fake-IP 热更新和 TUN 共存能力，需要另行设计 ABI。
- sing-ebpf `cb41c483`、`31b917a5`：连接 UDP 的 O(1) 恢复索引和 ring-buffer
  事件清理需要改动内核 map/ABI。当前仍使用有界查找、socket-release 与 LRU 回退。
  配套新诊断、map 容量调整及 cookie helper 微优化一并暂缓。
- 最新 `27de53a4` 的 TC UDP 条件删除：其 lookup/比较/delete 是分离的系统调用，
  用户态锁无法排除内核在比较后重写同一 key；本次保留 LRU，避免引入新的删除竞态。

## 上游来源变化

`CHIZI-0618/sing-box/testing-ebpf-tc-rewrite` 已不存在。后续后端开发位于
[`CHIZI-0618/sing-ebpf/dev`](https://github.com/CHIZI-0618/sing-ebpf/tree/dev)，
本次检查到 `27de53a4729d09c86cb93eed0a7b97caa97bc40f`。
sing-box 的 `ebpf-inbound` 位于 `9f7ab977`；TanakaLun 的 `ebpf-inbound` 位于
`94371fb4`，使用 sing-ebpf `a0edc850`。

内置后端仍有本分支特有的改动，不能用单个 sing-ebpf 提交号表示完整同步。
本次未改变 C 源码或已生成的 BPF 对象。

## 验证

- Windows：callback、dialer、Smart、outboundgroup、outbound 相关测试通过。
- WSL/Linux：上述模块以及 `common/ebpf`、`listener/sing_ebpf` 的 race 检查通过，
  受影响模块 `go vet -tags with_gvisor,with_ebpf` 通过。
- WSL/Linux 全仓 `CGO_ENABLED=1 go test -tags with_gvisor,with_ebpf -timeout 10m ./...`
  通过，包含入站协议并发互通测试。
- WSL root 的隔离网络/挂载命名空间：带 `with_ebpf,ebpf_integration` 的
  `common/ebpf` 测试通过 136 项；唯一跳过的是由父测试启动的 helper 入口。
  实际加载并执行 BPF 程序，覆盖 netd 接管/恢复、未知 owner 保护、旧程序回收、
  动态绕过控制刷新和回滚、非原子查询回退及已有数据面回归。
- Linux ARM64、Android ARM64、Windows AMD64
  `CGO_ENABLED=0 go build -tags with_gvisor,with_ebpf` 通过。
- `git diff --check` 通过；C 源码与 BPF 生成对象没有变化。

真实 Android/路由器设备不在本机测试范围内。
