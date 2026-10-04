#!/usr/bin/env bash
# 发布集合端到端演示（完全离线，仅用 Python 标准库）。
# 场景：共享依赖、循环依赖、部分签发者先后批准、中断后接续、
# 以及离线接收者检查集合完整性并定位缺失的可信依据。
set -euo pipefail

cd "$(dirname "$0")/.."
PY=${PYTHON:-python}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
STORE=$WORK/store
ART=$WORK/artifacts
mkdir -p "$ART"
T0=2026-01-01T00:00:00Z
T1=2026-02-01T00:00:00Z
T2=2026-03-01T00:00:00Z

tr() { $PY -m trusted_release --home "$STORE" "$@"; }

echo "== 0. 初始化信任库与签发者 =="
tr init
tr key-create --issuer sec     --scope '*' --now $T0
tr key-create --issuer builder --scope '*' --role build --now $T0
tr key-create --issuer qa-team --scope '*' --role qa    --now $T0

echo "== 1. 虚构制品：libbase 被 libmid 与 app 共享依赖 =="
echo libbase-v1 > "$ART/libbase.bin";  echo build-libbase > "$ART/libbase.BUILD"
echo libmid-v1  > "$ART/libmid.bin";   echo build-libmid  > "$ART/libmid.BUILD"
echo app-v1     > "$ART/app.bin";      echo build-app     > "$ART/app.BUILD"

tr set-candidate --name suite --set-version 2026.1 \
  --member libbase:1.0:"$ART/libbase.bin":"$ART/libbase.BUILD" \
  --member libmid:1.0:"$ART/libmid.bin":"$ART/libmid.BUILD" \
  --member app:1.0:"$ART/app.bin":"$ART/app.BUILD" \
  --dep libmid:libbase --dep app:libmid --dep app:libbase \
  --policy-id set-standard --policy-version 1 \
  --require build=1 --require qa=1 \
  --bundle "$WORK/set-candidate.json" --now $T0

echo "== 2. 部分签发者先批准，随后发生中断（法定人数不足，定稿失败）=="
tr set-approve --candidate "$WORK/set-candidate.json" --issuer builder \
  --output "$WORK/appr-build.json" --now $T0
if tr set-finalize --candidate "$WORK/set-candidate.json" \
     --approvals "$WORK/appr-build.json" \
     --bundle "$WORK/set-rel.json" --now $T1; then
  echo "!! 不应成功"; exit 1
else
  echo "-> 定稿被拒绝（缺少 qa 批准），可信目录中没有半个集合"
fi

echo "== 3. 中断后接续：补齐 qa 批准，整组一次性进入可信目录 =="
tr set-approve --candidate "$WORK/set-candidate.json" --issuer qa-team \
  --output "$WORK/appr-qa.json" --now $T1
tr set-finalize --candidate "$WORK/set-candidate.json" \
  --approvals "$WORK/appr-build.json" "$WORK/appr-qa.json" \
  --bundle "$WORK/set-rel.json" --now $T1

echo "== 4. 离线接收者验证完整集合 =="
tr set-verify --bundle "$WORK/set-rel.json" \
  --member libbase:"$ART/libbase.bin":"$ART/libbase.BUILD" \
  --member libmid:"$ART/libmid.bin":"$ART/libmid.BUILD" \
  --member app:"$ART/app.bin":"$ART/app.BUILD" --now $T1

echo "== 5. 离线接收者缺少 libbase：明确指出缺哪项可信依据 =="
if tr set-verify --bundle "$WORK/set-rel.json" \
     --member libmid:"$ART/libmid.bin" --member app:"$ART/app.bin" \
     --now $T1; then
  echo "!! 不应成功"; exit 1
fi

echo "== 6. 替换一个制品后，旧批准不能用于新集合 =="
echo libmid-v1.0.1-patched > "$ART/libmid.bin"
tr set-candidate --name suite --set-version 2026.1.1 \
  --member libbase:1.0:"$ART/libbase.bin":"$ART/libbase.BUILD" \
  --member libmid:1.0.1:"$ART/libmid.bin":"$ART/libmid.BUILD" \
  --member app:1.0:"$ART/app.bin":"$ART/app.BUILD" \
  --dep libmid:libbase --dep app:libmid --dep app:libbase \
  --policy-id set-standard --policy-version 1 \
  --require build=1 --require qa=1 \
  --bundle "$WORK/set-candidate2.json" --now $T1
if tr set-finalize --candidate "$WORK/set-candidate2.json" \
     --approvals "$WORK/appr-build.json" "$WORK/appr-qa.json" \
     --bundle "$WORK/set-rel2.json" --now $T1; then
  echo "!! 旧批准不应适用于新集合"; exit 1
else
  echo "-> 旧批准被拒绝：集合内容变化后必须重新批准"
fi

echo "== 7. 循环依赖（plug-a 与 plug-b 互相依赖）允许并如实报告 =="
echo plug-a > "$ART/plug-a.bin"; echo build-a > "$ART/plug-a.BUILD"
echo plug-b > "$ART/plug-b.bin"; echo build-b > "$ART/plug-b.BUILD"
tr set-candidate --name plugins --set-version 1.0 \
  --member plug-a:1.0:"$ART/plug-a.bin":"$ART/plug-a.BUILD" \
  --member plug-b:1.0:"$ART/plug-b.bin":"$ART/plug-b.BUILD" \
  --dep plug-a:plug-b --dep plug-b:plug-a \
  --policy-id set-standard --policy-version 1 \
  --require build=1 --require qa=1 \
  --bundle "$WORK/set-cyc.json" --now $T2
tr set-approve --candidate "$WORK/set-cyc.json" --issuer builder \
  --output "$WORK/cyc-build.json" --now $T2
tr set-approve --candidate "$WORK/set-cyc.json" --issuer qa-team \
  --output "$WORK/cyc-qa.json" --now $T2
tr set-finalize --candidate "$WORK/set-cyc.json" \
  --approvals "$WORK/cyc-build.json" "$WORK/cyc-qa.json" \
  --bundle "$WORK/set-cyc-rel.json" --now $T2
tr set-verify --bundle "$WORK/set-cyc-rel.json" \
  --member plug-a:"$ART/plug-a.bin" --member plug-b:"$ART/plug-b.bin" \
  --now $T2 --json | grep -A4 dependency_cycles || true

echo "== 8. 收集期间签发者被撤销：批准被重新解释，定稿失败 =="
tr set-candidate --name suite --set-version 2026.2 \
  --member libbase:1.0:"$ART/libbase.bin":"$ART/libbase.BUILD" \
  --member libmid:1.0.1:"$ART/libmid.bin":"$ART/libmid.BUILD" \
  --member app:1.0:"$ART/app.bin":"$ART/app.BUILD" \
  --dep libmid:libbase --dep app:libmid --dep app:libbase \
  --policy-id set-standard --policy-version 1 \
  --require build=1 --require qa=1 \
  --bundle "$WORK/set-candidate3.json" --now $T2
tr set-approve --candidate "$WORK/set-candidate3.json" --issuer builder \
  --output "$WORK/appr3-build.json" --now $T2
tr revoke --crl-issuer sec --issuer builder --key-versions 1 \
  --reason key-compromise --now $T2
tr set-approve --candidate "$WORK/set-candidate3.json" --issuer qa-team \
  --output "$WORK/appr3-qa.json" --now $T2
if tr set-finalize --candidate "$WORK/set-candidate3.json" \
     --approvals "$WORK/appr3-build.json" "$WORK/appr3-qa.json" \
     --bundle "$WORK/set-rel3.json" --now $T2; then
  echo "!! 被撤销签发者的批准不应再计入"; exit 1
else
  echo "-> 撤销后 builder 的批准不再计入法定人数"
fi

echo "== 9. 旧集合仍然可核验（内容寻址存储保留旧制品，按发布当时复盘）=="
tr set-verify --bundle "$WORK/set-rel.json" --now $T2 --as-of-release

echo "演示完成"
