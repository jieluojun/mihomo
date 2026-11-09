#!/bin/sh
# fork 的 Alpha = upstream/Alpha + fork 自己的提交（线性历史，
# 用 `git log upstream/Alpha..Alpha` 可以看到）。
# 同步 = git rebase：把 fork 提交挪到最新上游之上，不再经过补丁文件。
#
# 用法（在 mihomo 仓库根目录）:
#   sh /path/to/fork-sync/sync.sh
#
# 冲突时 rebase 会停在当前这个提交上：
#   git rebase --show-current-patch   # 查看当前冲突对应的改动
#   # 修好文件后
#   git add <文件>
#   git rebase --continue             # 处理下一个提交
#   git rebase --abort                # 放弃整个同步，回到同步前状态
#
# 完成后验证并强推（rebase 重写了历史，需要 --force-with-lease）:
#   go test ./adapter/outbound/ -run 'TestHttpConnectLine|TestCnsRequestHeader' -v
#   git push --force-with-lease origin Alpha

set -eu

UPSTREAM="${UPSTREAM:-https://github.com/liuran001/mihomo.git}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-Alpha}"
ORIGIN_BRANCH="${ORIGIN_BRANCH:-Alpha}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "请在 mihomo 仓库根目录运行" >&2
  exit 1
fi

git remote get-url upstream >/dev/null 2>&1 || git remote add upstream "$UPSTREAM"
git fetch upstream "$UPSTREAM_BRANCH"

git checkout "$ORIGIN_BRANCH"

if git merge-base --is-ancestor "upstream/$UPSTREAM_BRANCH" "$ORIGIN_BRANCH"; then
  echo "$ORIGIN_BRANCH 已包含 upstream/$UPSTREAM_BRANCH，无需同步"
  exit 0
fi

echo "fork 提交（将 rebase 到 upstream/$UPSTREAM_BRANCH 之上）:"
git log --oneline "upstream/$UPSTREAM_BRANCH..$ORIGIN_BRANCH"
echo

git rebase "upstream/$UPSTREAM_BRANCH"

echo
echo "完成: $ORIGIN_BRANCH = upstream/$UPSTREAM_BRANCH + 下列 fork 提交"
git log --oneline "upstream/$UPSTREAM_BRANCH..$ORIGIN_BRANCH"
echo
echo "验证: go test ./adapter/outbound/ -run 'TestHttpConnectLine|TestCnsRequestHeader' -v"
echo "推送: git push --force-with-lease origin $ORIGIN_BRANCH"
