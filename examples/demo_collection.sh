#!/usr/bin/env bash
# 发布集合端到端演示（虚构制品，完全离线）：
#   共享依赖 app->lib 与 plugA->lib、循环依赖 plugA<->plugB、
#   部分签发者先批准后补齐、收集中途撤销后重新解释、中断后接续、
#   离线接收者核验集合完整性并定位缺失的可信依据。
set -euo pipefail
cd "$(dirname "$0")/.."

DEMO=/tmp/tr-collection-demo
STORE=$DEMO/store
WORK=$DEMO/work
rm -rf "$DEMO"; mkdir -p "$WORK"
TR="python -m trusted_release --home $STORE"

echo "== 0. 初始化信任库与签发者 =="
$TR init
$TR key-create --issuer sec --scope '*'
$TR key-create --issuer build --scope '*' --role build
$TR key-create --issuer qa --scope '*' --role qa

echo "== 1. 虚构制品：app 依赖 lib；plugA/plugB 互相依赖且共享 lib =="
echo "app binary v2"      > $WORK/app-2.0.tar
echo "build app"          > $WORK/APP.BUILD
echo "lib binary v1.3"    > $WORK/lib-1.3.tar
echo "build lib"          > $WORK/LIB.BUILD
echo "plugin A"           > $WORK/plugA-1.0.tar
echo "build A"            > $WORK/PA.BUILD
echo "plugin B"           > $WORK/plugB-1.0.tar
echo "build B"            > $WORK/PB.BUILD

$TR collection-candidate --name platform --version 2026.10 \
  --member app:2.0:$WORK/app-2.0.tar:$WORK/APP.BUILD \
  --member lib:1.3:$WORK/lib-1.3.tar:$WORK/LIB.BUILD \
  --member plugA:1.0:$WORK/plugA-1.0.tar:$WORK/PA.BUILD \
  --member plugB:1.0:$WORK/plugB-1.0.tar:$WORK/PB.BUILD \
  --dep app:2.0=lib:1.3 \
  --dep plugA:1.0=plugB:1.0 --dep plugB:1.0=plugA:1.0 \
  --dep plugA:1.0=lib:1.3 \
  --policy-id standard --policy-version 1 --require build=1 --require qa=1 \
  --bundle $WORK/candidate.json

echo "== 2. 部分批准：只有 build 先签，finalize 失败且目录不出现半份集合 =="
$TR collection-approve --candidate $WORK/candidate.json --issuer build --output $WORK/build.json
if $TR collection-finalize --candidate $WORK/candidate.json \
     --approvals $WORK/build.json --bundle $WORK/rel.json; then
  echo "UNEXPECTED: quorum not met but finalized"; exit 1
fi
$TR collection-list

echo "== 3. 收集期间 build 密钥被撤销：旧批准重新解释后不再计数 =="
$TR revoke --crl-issuer sec --issuer build --key-versions 1 --reason compromised
$TR key-create --issuer build2 --scope '*' --role build
$TR collection-approve --candidate $WORK/candidate.json --issuer build2 --output $WORK/build2.json
$TR collection-approve --candidate $WORK/candidate.json --issuer qa --output $WORK/qa.json

echo "== 4. 中断后接续：补齐可信批准，整组原子进入可信目录 =="
$TR collection-finalize --candidate $WORK/candidate.json \
  --approvals $WORK/build.json $WORK/build2.json $WORK/qa.json \
  --bundle $WORK/rel.json
$TR collection-list

echo "== 5. 离线接收者核验整组完整性 =="
$TR collection-verify --bundle $WORK/rel.json

echo "== 6. 缺失可信依据时明确报告（移除 qa 批准） =="
python - "$WORK/rel.json" "$WORK/rel-noqa.json" <<'EOF'
import json, sys
rec = json.load(open(sys.argv[1]))
rec["approvals"] = [a for a in rec["approvals"] if a["approval"]["role"] != "qa"]
json.dump(rec, open(sys.argv[2], "w"), indent=2, sort_keys=True)
EOF
if $TR collection-verify --bundle $WORK/rel-noqa.json; then
  echo "UNEXPECTED: missing qa approval but verified"; exit 1
fi

echo "== 7. 替换集合内一个制品 => 新集合，旧批准不再适用 =="
echo "app binary v2 HOTFIX" > $WORK/app-2.0.tar
$TR collection-candidate --name platform --version 2026.10 \
  --member app:2.0:$WORK/app-2.0.tar:$WORK/APP.BUILD \
  --member lib:1.3:$WORK/lib-1.3.tar:$WORK/LIB.BUILD \
  --member plugA:1.0:$WORK/plugA-1.0.tar:$WORK/PA.BUILD \
  --member plugB:1.0:$WORK/plugB-1.0.tar:$WORK/PB.BUILD \
  --dep app:2.0=lib:1.3 \
  --dep plugA:1.0=plugB:1.0 --dep plugB:1.0=plugA:1.0 \
  --dep plugA:1.0=lib:1.3 \
  --policy-id standard --policy-version 1 --require build=1 --require qa=1 \
  --bundle $WORK/candidate2.json
if $TR collection-finalize --candidate $WORK/candidate2.json \
     --approvals $WORK/build2.json $WORK/qa.json --bundle $WORK/rel2.json; then
  echo "UNEXPECTED: stale approvals accepted for new collection"; exit 1
fi

echo "== 8. 旧集合仍然可核验 =="
$TR collection-verify --bundle $WORK/rel.json
echo "DEMO OK"

