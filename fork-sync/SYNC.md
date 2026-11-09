# 只保留 Alpha：拉上游后重新 `git am` 补丁

不再维护 `with-at` 分支。fork 上只留 **`Alpha`** = `liuran001/mihomo` 的 Alpha + `fork-sync/0001`…`0007` 补丁。

上游一更新：硬重置到上游，再按顺序打补丁（不 rebase）。冲突时停在那张补丁上修，比 rebase 一整串提交更直观。

## 一、一次性切过去（有 with-at 的 fork）

补丁目录用本包的 `fork-sync/`（含 0001–0007）。在 **干净** 的 mihomo 仓库里：

```bash
git remote add upstream https://github.com/liuran001/mihomo.git   # 已有可跳过
git fetch upstream origin
git checkout -B Alpha
git reset --hard upstream/Alpha

# 把补丁和工作流放到树上（下次同步还靠它们）
mkdir -p fork-sync .github/workflows
cp /path/to/fork-sync/000*.patch fork-sync/
cp /path/to/fork-sync/sync-and-build.yml .github/workflows/sync-and-build.yml
git add fork-sync .github/workflows
git commit -m "ci: keep sync workflow and patch series on Alpha"

git am --3way fork-sync/000*.patch

git push -f origin Alpha
git push origin --delete with-at    # 确认 Alpha 没问题再删
```

仓库默认分支保持 **Alpha**。

## 二、每次上游更新（Termux / 电脑）

仓库根目录：

```bash
sh /path/to/fork-sync/sync.sh
git push -f origin Alpha
```

等价手打：

```bash
git fetch upstream
git checkout Alpha
git reset --hard upstream/Alpha
git am --3way fork-sync/000*.patch    # 若 reset 掉了 fork-sync，先从备份/本包拷回来
git push -f origin Alpha
```

`reset --hard` 会清掉工作区里的补丁文件。所以要么：

- 用 `sync.sh`（从脚本所在目录读补丁，不依赖树上的 `fork-sync/`），或
- reset 之前把 `fork-sync/` 拷到 `/tmp`，reset 后再拷回来再 `git am`。

## 三、冲突

`git am` 失败会停在**当前这一张**补丁：

```bash
# 看失败
git am --show-current-patch
# 修文件后
git add <文件>
git am --continue
# 放弃
git am --abort
```

| 文件 | 处理 |
|---|---|
| `adapter/outbound/http.go` | 保住 `Path`/`DelHost`、`connectTarget`、With-At / Baidu-Direct / del_host |
| `adapter/outbound/cns.go` | 保住 `camouflageHost` 和 `CONNECT host:443`（0007） |
| `constant/features/tags.go` | 两边 tag 都留 |
| `component/updater/update_core.go` | 保留 `with-at-latest` 下载地址 |

```bash
go test ./adapter/outbound/ -run 'TestHttpConnectLine|TestCnsRequestHeader' -v
```

## 四、GitHub Actions

把 `sync-and-build.yml` 放在 **Alpha** 的 `.github/workflows/`。每天 04:00（北京）或手动 Run workflow：

1. 把当前 `fork-sync/*.patch` 和工作流拷走  
2. `reset --hard upstream/Alpha`  
3. 提交工作流 + 补丁文件  
4. `git am --3way fork-sync/000*.patch`  
5. 强推 `Alpha`，编译并发布 `with-at-latest`

Actions 权限：Settings → Actions → General → **Read and write permissions**。

另外必须加 Secret **`SYNC_PAT`**：经典 PAT，勾选 **repo + workflow**。  
`GITHUB_TOKEN` 不能创建/更新 `.github/workflows/`（上游 Alpha 带 `test.yml`，reset 之后强推会被拒：`without workflows permission`）。把 PAT 填进 Settings → Secrets and variables → Actions → `SYNC_PAT`，工作流的 checkout 用这个 token 推送。

冲突时 workflow 变红，按「三」在本地修好再推，不要让 CI 瞎合并。

## 五、补丁清单（打的顺序）

| 补丁 | 内容 |
|---|---|
| 0001 | HTTP With-At / Baidu-Direct |
| 0002 | `with_ebpf` 版本标签 |
| 0003 | updater 走 with-at-latest |
| 0004 | TPBox path / del_host（含 del_host 时去掉默认 UA） |
| 0005 | CNS 协议 + 伪装 Host 写到 CONNECT 行 |

不要再打旧的 0005-UA / 0006 / 0007：已分别并进 0004 和 0005。

新增补丁：做成 `0006-….patch` 放进 `fork-sync/`，下次同步会自动打上。
