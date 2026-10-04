#!/usr/bin/env bash
# 发布集合版本对照报告演示（完全离线）：
#   审批人员选择两个已发布集合，生成对照报告——制品内容、依赖关系
#   （共享依赖、循环依赖）与所需批准角色的变化，逐项解释哪些旧批准
#   不再适用、需要补齐哪些批准。报告离线保存并关联两个集合的摘要；
#   不自动继承批准，也不改写已发布集合。
set -euo pipefail
cd "$(dirname "$0")/.."

DEMO=/tmp/tr-collection-compare-demo
STORE=$DEMO/store
WORK=$DEMO/work
rm -rf "$DEMO"; mkdir -p "$WORK"
TR="python -m trusted_release --home $STORE"

echo "== 0. 初始化信任库与签发者 =="
$TR init
$TR key-create --issuer sec --scope '*'
$TR key-create --issuer build --scope '*' --role build
$TR key-create --issuer qa --scope '*' --role qa
$TR key-create --issuer secops --scope '*' --role secops

echo "== 1. 虚构制品：app/plugA 共享依赖 lib；plugA<->plugB 循环依赖 =="
echo "app binary v2"   > $WORK/app.tar;   echo "build app" > $WORK/APP.BUILD
echo "lib binary v1.3" > $WORK/lib.tar;   echo "build lib" > $WORK/LIB.BUILD
echo "plugin A"        > $WORK/pa.tar;    echo "build A"   > $WORK/PA.BUILD
echo "plugin B"        > $WORK/pb.tar;    echo "build B"   > $WORK/PB.BUILD

publish() {  # <version> <policy-version> <require...>
  local ver=$1; shift
  local pver=$1; shift
  $TR collection-candidate --name platform --version "$ver" \
    --member app:2.0:$WORK/app.tar:$WORK/APP.BUILD \
    --member lib:1.3:$WORK/lib.tar:$WORK/LIB.BUILD \
    --member plugA:1.0:$WORK/pa.tar:$WORK/PA.BUILD \
    --member plugB:1.0:$WORK/pb.tar:$WORK/PB.BUILD \
    --dep app:2.0=lib:1.3 \
    --dep plugA:1.0=plugB:1.0 --dep plugB:1.0=plugA:1.0 \
    --dep plugA:1.0=lib:1.3 \
    --policy-id standard --policy-version "$pver" \
    $(for r in "$@"; do echo --require $r; done) \
    --bundle $WORK/cand-$ver.json
  local ap=()
  for r in "$@"; do
    local issuer=${r%=*}
    $TR collection-approve --candidate $WORK/cand-$ver.json \
      --issuer "$issuer" --output $WORK/ap-$ver-$issuer.json
    ap+=($WORK/ap-$ver-$issuer.json)
  done
  $TR collection-finalize --candidate $WORK/cand-$ver.json \
    --approvals "${ap[@]}" --bundle $WORK/rel-$ver.json
}

echo "== 2. 发布旧集合 2026.10（build+qa 批准） =="
publish 2026.10 1 build=1 qa=1

echo "== 3. 单个制品替换（app 热修）+ 策略增加 secops 角色 => 新集合 2026.11 =="
echo "app binary v2 HOTFIX" > $WORK/app.tar
publish 2026.11 2 build=1 qa=1 secops=1

echo "== 4. 审批人员生成版本对照报告（离线保存，关联两个集合摘要） =="
$TR collection-compare --old $WORK/rel-2026.10.json --new $WORK/rel-2026.11.json \
  --output $WORK/compare-report.json
python - "$WORK/compare-report.json" <<'EOF'
import json, sys
r = json.load(open(sys.argv[1]))
print("report_id:", r["report_id"])
print("old:", r["old"]["collection_release_id"], "-> new:", r["new"]["collection_release_id"])
print("replaced:", [c["product"] for c in r["content_changes"]["replaced"]])
print("cycles old:", r["dependency_changes"]["cycles_old"])
print("shared deps:", [s["product"] for s in r["dependency_changes"]["shared_dependencies_new"]])
print("roles added:", r["policy_changes"]["requirements_added"])
for s in r["approval_analysis"]["stale_approvals"]:
    print("stale:", s["issuer_id"], s["role"], "-", s["reason"])
for t in r["approval_analysis"]["approvals_to_collect"]:
    print("collect:", t["role"], "x", t["required"])
EOF

echo "== 5. 报告不继承批准、不改写已发布集合：两个集合仍可独立核验 =="
$TR collection-verify --bundle $WORK/rel-2026.10.json
$TR collection-verify --bundle $WORK/rel-2026.11.json
$TR collection-list
echo "DEMO OK"

