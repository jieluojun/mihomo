#!/bin/sh
# 只保留 Alpha：fetch 上游 → reset 到 upstream/Alpha → 重新 git am 补丁。
# 用法（在 mihomo 仓库根目录）:
#   sh /path/to/fork-sync/sync.sh
# 补丁和本脚本可以放在仓库外，也可以放在仓库的 fork-sync/：
# reset 前会先拷到临时目录，所以脚本不会把自己删掉。

set -eu

UPSTREAM="${UPSTREAM:-https://github.com/liuran001/mihomo.git}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-Alpha}"
ORIGIN_BRANCH="${ORIGIN_BRANCH:-Alpha}"
PATCH_DIR="${PATCH_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "请在 mihomo 仓库根目录运行" >&2
  exit 1
fi

git remote get-url upstream >/dev/null 2>&1 || git remote add upstream "$UPSTREAM"
git fetch upstream "$UPSTREAM_BRANCH"

# reset --hard 会清掉工作区，先把整个补丁目录拷走
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp -a "$PATCH_DIR"/. "$tmp/"
set -- "$tmp"/[0-9][0-9][0-9][0-9]-*.patch
if [ ! -f "$1" ]; then
  echo "没有在 $PATCH_DIR 找到 0001-*.patch" >&2
  exit 1
fi

echo "应用补丁:"
for p in "$@"; do
  echo "  $(basename "$p")"
done

git checkout -B "$ORIGIN_BRANCH"
git reset --hard "upstream/$UPSTREAM_BRANCH"
git am --3way "$@"

# 把 fork-sync（脚本、补丁、README）和工作流放回树上，下次同步还在
root="$(git rev-parse --show-toplevel)"
mkdir -p "$root/fork-sync"
cp -a "$tmp"/. "$root/fork-sync/"
if [ -f "$tmp/sync-and-build.yml" ]; then
  mkdir -p "$root/.github/workflows"
  cp "$tmp/sync-and-build.yml" "$root/.github/workflows/sync-and-build.yml"
fi
git add fork-sync
[ -f "$root/.github/workflows/sync-and-build.yml" ] && git add .github/workflows/sync-and-build.yml
if ! git diff --cached --quiet; then
  git add -A fork-sync .github/workflows/sync-and-build.yml 2>/dev/null || true
  git commit -m "ci: keep sync workflow and patch series on Alpha"
fi

echo
echo "完成: $ORIGIN_BRANCH = upstream/$UPSTREAM_BRANCH + $# 个补丁"
echo "推送: git push -f origin $ORIGIN_BRANCH"
