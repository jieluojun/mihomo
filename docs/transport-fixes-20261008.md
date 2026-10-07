# 传输层回归问题修复（2026-10-08）

跟进 [eBPF 适配验证](upstream-adaptation-20261007.md) 中发现的互通失败和并发竞争。

## SMUX 写入队列的缓冲区所有权

race 堆栈虽然落在 HTTP/2/TLS 写入处，冲突的另一方实际上是 SMUX 的发送队列。`writeFrameInternal` 在超时、会话关闭或底层写入失败时可以提前返回，但队列仍保存调用方传入的切片。调用方随后复用 TLS 缓冲区时，`sendLoop` 可能仍在读取它。

发送队列现在复制非空 payload，独立持有数据；取消行为和线协议不变。每个非空帧增加一次分配和复制。上游 `metacubex/smux` HEAD 仍是 `d0c8756d3141`，因此通过 `third_party/smux` 和 Go module replacement 固定修补版本，保留原许可证与来源说明。生产源文件相对该版本仅修改这处队列所有权逻辑。

新增回归测试覆盖 deadline、会话 close 和 socket error 三种提前返回路径：旧实现全部失败，修复后全部通过。

## TLSMirror 的双向 nonce

TLS 1.2 显式 nonce 路径原先在写 C2S 数据时也调用 S2C 计数器，导致两个发送 goroutine 交叉修改同一状态。现在每个方向只递增自己的计数器。新增双向并行回归测试在旧代码上稳定检测到 race 和序号跳变，修复后通过。

## V2Ray 互通测试启动同步

测试原先把 TCP 端口可连接当作 V2Ray 子进程已经启动。在普通 WSL 网络下，TLSMirror 测试间歇出现握手 EOF，失败时子进程甚至尚未输出启动日志；同一二进制在隔离网络中连续 30 次通过。

测试现在先等待 V2Ray 在所有功能启动完成后输出的启动消息，再探测端口。标准输出缓冲区同步读写，支持启动消息分片到达，并区分版本横幅和真正的启动完成消息。修改后原失败用例在普通 WSL 环境连续 5 次通过。

## 验证记录

- `transport/tlsmirror`、`transport/xhttp` 和本地 SMUX 回归测试通过 race 检查。
- 原 XHTTP ECH/SMUX 失败路径重复 3 次通过 race 检查。
- 扩展压力测试中的 TLSMirror gRPC/uTLS 和 XHTTP packet-up/split/YAMUX 连接取消失败，分别在独立进程重复 10 次通过 race 检查；此前失败轮次同时运行大量压力测试与构建，出现了内存耗尽。
- SMUX 原始全套 race 测试在 `Test8GBTransferV1` 达到 5 分钟限制；该次执行不能作为全套通过的依据。
- 将修补后的源码放入原始 SMUX 测试集，排除 1GB/8GB 大传输压力项后，全部常规测试通过 race 检查（35 秒）；未改动或放宽这些测试的断言。
- 最终全仓常规回归通过：`GOMAXPROCS=2 go test -p 1 -parallel 4 -tags with_gvisor,with_ebpf -timeout 15m ./...`，其中 `listener/inbound` 用时 772 秒，互通测试未跳过。
- Linux ARM64、Android ARM64、Windows AMD64 使用 `with_gvisor,with_ebpf` 顺序构建，全部通过。
- `transport/tlsmirror` 和本地 SMUX 的 `go vet` 通过。
