# 只保留 Alpha：拉上游后把 fork 提交 rebase 上去

fork 上只留 **`Alpha`** = `liuran001/mihomo` 的 Alpha + fork 自己的提交（线性历史）。
fork 的改动就是 Alpha 分支上的普通 git 提交，用 `git log upstream/Alpha..Alpha` 即可列出，
**不再使用 `fork-sync/*.patch` 补丁文件**，也没有 `.last-built-upstream` 之类的状态文件。

上游一更新：`fetch → rebase → 解决冲突 → 强推`。冲突时 rebase 会逐个停在当前提交上处理，
与以前 `git am` 停在某一张补丁上的体验一致，但不需要维护补丁副本。

> 2026-11 起从补丁方式切换为提交方式。此前已经通过 `git am` 进历史的 5 个提交
> （With-At / Baidu-Direct、with_ebpf 标签、updater 地址、TPBox path / del_host、CNS 协议）
> 本身就是 fork 的真实提交，切换时无需重建，直接沿用。

## 一、每次上游更新（Termux / 电脑）

仓库根目录：

```bash
sh /path/to/fork-sync/sync.sh   # fetch upstream + rebase
go test ./adapter/outbound/ -run 'TestHttpConnectLine|TestCnsRequestHeader' -v
git push --force-with-lease origin Alpha
```

`Alpha` 已经包含上游最新提交时，脚本会提示"无需同步"并退出。

等价手打：

```bash
git fetch upstream
git checkout Alpha
git rebase upstream/Alpha
git push --force-with-lease origin Alpha
```

不想强推时可以改用 merge（历史会多一个合并气泡，不用 `--force-with-lease`）：

```bash
git fetch upstream
git merge upstream/Alpha
git push origin Alpha
```

## 二、冲突

`git rebase` 失败会停在**当前这一个**提交上：

```bash
git rebase --show-current-patch   # 查看当前提交的改动
# 修文件
git add <文件>
git rebase --continue             # 处理下一个提交
git rebase --abort                # 放弃整个同步，回到同步前状态
```

| 文件 | 处理 |
|---|---|
| `adapter/outbound/http.go` | 保住 `Path`/`DelHost`、`connectTarget`、With-At / Baidu-Direct / del_host |
| `adapter/outbound/cns.go` | 保住 `camouflageHost` 和 `CONNECT host:443` 伪装逻辑 |
| `constant/features/tags.go` | 两边 tag 都留 |
| `component/updater/update_core.go` | 保留 with-at-latest 下载地址（指向 jieluojun/mihomo 的 Prerelease-Alpha 滚动 Release） |

```bash
go test ./adapter/outbound/ -run 'TestHttpConnectLine|TestCnsRequestHeader' -v
```

## 三、新增 fork 功能

直接在 `Alpha` 上开发、提交（一个功能一个提交），正常 push 即可。
**不要**再往 `fork-sync/` 里放 `.patch` 文件——fork-sync/ 现在只放同步脚本和说明文档。
提交信息沿用现有格式：`feat(...): ...` / `fix(...): ...`。

## 四、GitHub Actions

`.github/workflows/sync-and-build.yml` 已删除：不再有"每 30 分钟检查上游 → 重置 → am → 编译全架构 → 发布滚动 Release"的自动化。
上游同步与构建改为手动（按上文）。以下随之废弃：

- Secret **`SYNC_PAT`**（Settings → Secrets and variables → Actions 里可以删掉）
- `fork-sync/.last-built-upstream` 状态文件
- "Keep workflow permissions = Read and write" 仅为自动推送准备，按需保留即可

其它工作流（`build.yml`、`androidarm64.yml`、`ebpf.yml`、`test.yml` 等）不受影响。

## 五、fork 提交清单

```bash
git log --oneline upstream/Alpha..Alpha
```

当前应看到的 fork 提交（内容与旧 `fork-sync/0001`…`0005` 补丁一一对应；rebase 后哈希会变）：

| 提交主题 | 内容 |
|---|---|
| `feat(http): port With-At & Baidu-Direct pseudo headers from PuerNya/sing` | HTTP With-At / Baidu-Direct |
| `feat(features): show with_ebpf tag; normalize Version suffix to -zero` | `with_ebpf` 版本标签 |
| `fix(updater): keep With-At builds on fork release` | updater 走 fork 的 Prerelease-Alpha |
| `feat(http): port TPBox path and del_host CONNECT options` | TPBox path / del_host |
| `feat: add CNS protocol (outbound + inbound)` | CNS 协议 |

历史里还可能有若干 `ci:` 提交（如 "ci: keep sync workflow and patch series on Alpha"、"ci: record successfully built upstream …"），
它们的内容已被后续提交删除/取代。想清理的话可以在下次同步后用 `git rebase -i` squash 掉，非必须。
