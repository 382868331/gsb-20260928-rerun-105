# 软件制品可信发布系统（Trusted Software Artifact Release）

纯 Python 标准库实现，完全离线可用。提供制品登记、构建说明绑定、
密码学签发与离线验证，并覆盖签发者轮换、证明过期与撤销资料版本管理。

## 信任模型

一次发布对应一份**证明（attestation）**，其签名同时绑定三类信息，
验证时三者必须同时成立，缺一不可：

1. **内容（Content）**：当前待验制品哈希 == 证明内 `artifact_digest`；
   当前构建说明哈希 == 证明内 `build_spec_digest`。制品按内容寻址存储，
   替换文件必然改变哈希，因此无法复用旧签名为新内容背书。
2. **签发者（Signer）**：签名用**当前**信任库中的签发者公钥验证通过，
   且该密钥当前状态为 `active`、处于适用时间窗内、未被当前撤销列表撤销。
3. **适用范围（Scope）**：密钥声明的 `scope` 必须覆盖被签发的产品，
   证明内 `scope` 必须与密钥一致。

历史发布始终保留、可查看；但**重新验证一律按当前指定的信任条件判断**：
轮换后的旧密钥默认不再可信、过期证明失效、被撤销密钥签发的历史发布
立即失效（即使签名本身仍然有效）。

## 关键机制

- **签发者轮换**：`issuers/keys.json` 中密钥带版本号。新建密钥时旧密钥
  自动置为 `rotated`，仅最新版本可签发；历史记录保留旧版本。
- **证明过期**：`not_before` / `expires_at` 在签名载荷内，验证时按
  当前时间判断，无法被篡改延期。
- **撤销资料版本管理**：CRL 存于 `crl/versions/NNNNNN.json`，每次撤销
  产生一份**签名、不可变、带版本号**的快照，`crl/current.json` 指向当前
  版本。历史快照保留可审计；验证只采用当前快照。CRL 自身签名失效时
  验证**失败关闭（fail-closed）**。
- **发布中断安全**：发布顺序为「登记内容 → 签名 → 最后原子更新索引」。
  任何前置步骤失败都不会向 `index.json` 写入条目，因此失败产物不可能
  被当作可信版本。

## 多签发者批准（policy-based quorum）

发布可由多个独立签发者共同批准，发布策略规定所需角色与数量：

- **发布策略**：`policies/versions/NNNNNN.json` 为签名、不可变、带版本号
  的策略快照，声明每个角色需要的独立批准数（`roles`）以及签发者的角色
  分配（`assignments`）。`policies/current.json` 指向当前版本。
- **候选（candidate）**：`begin` 为每次发布尝试生成唯一候选 ID（随机
  nonce + 内容绑定），并钉住当时的策略版本。重试产生新候选，**不同候选
  的批准不能混合**——即使文件内容完全相同。
- **批准（approval）**：每个批准在签名载荷内绑定候选 ID、制品哈希、构建
  说明哈希与策略版本，因此无法挪用到内容相同但发布条件不同的另一份记录。
- **凑数规则**：同一签发者对同一候选只能批准一次；验证时重复的签发者
  只计一次（多余条目标记 `duplicate_signer`），角色不符、密钥被撤销/
  轮换、签名无效、策略版本不符的批准都会被逐条说明并不计入法定数。
- **进入可信目录**：只有 `finalize` 时法定数满足才会原子写入索引；
  缺少批准、构建说明被替换、部分签发失败都不会留下任何可信条目。

### 双重信任评估

发布记录在 `finalize` 时冻结一份 `trust_snapshot`（当时的密钥状态、
CRL 快照、策略快照）。`verify --evaluation` 支持：

- `current`（默认）：按**当前**信任库与当前 CRL 判定；
- `release_time`：按**发布当时**冻结的信任条件判定；
- `both`：两者同时成立才算可信。

报告中 `checks.evaluations` 始终同时给出两种结论及每条批准的逐项
判定理由，旧发布材料本身保持不变。

### 多签发者命令行用法

```bash
python -m trusted_release --home store policy-set --policy-issuer sec \
    --role build:2 --role qa:1 \
    --assign builder-1:build --assign builder-2:build --assign qa-1:qa
CAND=$(python -m trusted_release --home store begin \
    --artifact app.tar.gz --build-spec BUILD.md --product app --version 1.0 \
    | cut -d' ' -f1 | cut -d= -f2)
python -m trusted_release --home store approve --candidate $CAND --issuer builder-1
python -m trusted_release --home store approve --candidate $CAND --issuer builder-2
python -m trusted_release --home store approve --candidate $CAND --issuer qa-1
python -m trusted_release --home store finalize --candidate $CAND --bundle rel.json
python -m trusted_release --home store verify \
    --artifact app.tar.gz --build-spec BUILD.md --bundle rel.json \
    --evaluation both --json
```

## 存储布局

```
store/
  registry/
    artifacts/sha256/<xx>/<digest>   # 内容寻址的制品与构建说明
    manifests/<digest>.json           # 制品+构建说明绑定
    releases/<release_id>.json        # 不可变发布记录（含证明与签名）
    index.json                        # 可信版本目录（最后原子写入）
  issuers/
    keys.json                         # 版本化签发者公钥与状态
    private/<issuer>.v<n>.key         # 签发私钥（0600，勿随包分发）
  crl/
    versions/000001.json ...          # 签名、版本化的撤销快照
    current.json                      # 当前快照指针
  policies/
    versions/000001.json ...          # 签名、版本化的发布策略快照
    current.json                      # 当前策略指针
```

多签发者流程还会在 `registry/candidates/` 下保存进行中的候选及其
已收集的批准；候选未通过 `finalize` 法定数校验前不会进入索引。

```
```

## 命令行用法

```bash
python -m trusted_release --home store init
python -m trusted_release --home store key-create --issuer sec --scope '*'
python -m trusted_release --home store key-create --issuer build --scope 'product:app'
python -m trusted_release --home store publish \
    --artifact app.tar.gz --build-spec BUILD.md \
    --product app --version 1.0 --issuer build --bundle rel.json
python -m trusted_release --home store verify \
    --artifact app.tar.gz --build-spec BUILD.md --bundle rel.json
python -m trusted_release --home store key-create --issuer build --scope 'product:app'  # 轮换
python -m trusted_release --home store revoke --crl-issuer sec --issuer build --key-versions 1
python -m trusted_release --home store list      # 历史发布
python -m trusted_release --home store crl-list  # 撤销资料历史版本
```

`verify` 成功退出码 0，失败 3（不可信）。`--now` 可注入时间以便测试
过期/轮换场景。离线环境只需携带发布包 `rel.json`、待验文件以及当前
信任库（签发者公钥 + 当前 CRL）。

## 密码学说明

`trusted_release/ed25519.py` 为 RFC 8032 Ed25519 纯标准库实现，
已通过 RFC 8032 测试向量并与系统 OpenSSL 做签名互操作校验。
生产环境可将该模块替换为原生/库实现，接口保持不变。

## 测试

```bash
python -m pytest tests/ -q
```

覆盖：正常签发/离线验证、制品内容替换、构建说明替换、证明错配
（用另一文件的有效签名为当前文件背书）、签发者轮换后历史可查但
重验失败、证明过期、撤销使历史发布失效、CRL 版本累积与篡改失败
关闭、适用范围不匹配、发布中断不留可信索引。
