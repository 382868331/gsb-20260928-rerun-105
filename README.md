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

- **多签发者策略门控**：策略以完整不可变版本（`policy_id`、`policy_version`
  和各角色所需独立签发者数量）绑定到候选与每份批准。验证只统计签名有效、
  当前或指定时点可信、角色和范围匹配的批准；同一签发者的多份批准不能重复
  凑数，即使声明成不同角色也只计一次。
- **候选隔离**：每次重试都生成带随机 nonce 的新候选，批准签名绑定候选
  digest、具体制品哈希、构建说明哈希以及完整策略版本。内容相同但策略版本
  或发布条件不同的记录不能互换批准；不同候选的批准也不能在 finalize 时混合。
- **发布当时/当前双结论**：旧发布材料不可变。默认按当前公钥状态与当前 CRL
  验证；`--as-of-release` 使用记录中的发布时间与发布时 CRL 版本复盘当时结论。
  后续撤销或轮换可使当前结论失败，但不会改写发布当时结论。

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
- **发布集合（release set）**：多个相互依赖的制品组成一个集合并整体
  批准。集合候选 digest 绑定每个成员的制品哈希、构建说明哈希以及
  全部依赖声明（`depends_on`），因此替换任一制品或改动任一依赖边
  都会得到全新集合，旧批准自动失效。批准允许先部分收集、稍后补齐；
  `set-finalize` 在收集完成时按**当前**信任条件重新解释每份批准
  （策略版本变化、签发者撤销都会立即体现），法定人数满足后整组
  原子写入可信目录——要么整组出现，要么完全不存在半个集合。
  依赖声明的是「允许一起使用」而非构建顺序：共享依赖自然表达，
  循环依赖允许存在并如实报告。历史集合永久保留，旧集合始终可核验。

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
```

## 命令行用法

```bash
python -m trusted_release --home store init
python -m trusted_release --home store key-create --issuer sec --scope '*'
python -m trusted_release --home store key-create --issuer build --scope 'product:app'
python -m trusted_release --home store publish \
    --artifact app.tar.gz --build-spec BUILD.md \
    --product app --version 1.0 --issuer build --bundle rel.json
python -m trusted_release --home store key-create --issuer qa --scope 'product:app' --role qa
python -m trusted_release --home store candidate \
    --artifact app.tar.gz --build-spec BUILD.md \
    --product app --version 2.0 --policy-id standard --policy-version 3 \
    --require build=1 --require qa=1 --bundle candidate.json
python -m trusted_release --home store approve --candidate candidate.json --issuer build --output build.json
python -m trusted_release --home store approve --candidate candidate.json --issuer qa --output qa.json
python -m trusted_release --home store finalize \
    --candidate candidate.json --approvals build.json qa.json --bundle rel-v2.json
python -m trusted_release --home store verify \
    --artifact app.tar.gz --build-spec BUILD.md --bundle rel.json
python -m trusted_release --home store verify \
    --artifact app.tar.gz --build-spec BUILD.md --bundle rel-v2.json --json
python -m trusted_release --home store verify \
    --artifact app.tar.gz --build-spec BUILD.md --bundle rel-v2.json --as-of-release
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

## 发布集合（release set）

多个相互依赖的制品组成一个集合，批准覆盖集合整体。集合候选 digest
绑定每个成员的制品哈希、构建说明哈希与全部依赖声明（`depends_on`），
替换任一制品或改动任一依赖边都会得到全新集合，旧批准自动失效。
批准可先部分收集、稍后补齐；`set-finalize` 在收集完成时按**当前**
信任条件重新解释每份批准（策略版本变化、签发者撤销立即体现），
法定人数满足后整组原子写入可信目录——要么整组出现，要么不存在
半个集合。依赖声明的是「允许一起使用」而非构建顺序：共享依赖自然
表达，循环依赖允许存在并如实报告。历史集合永久保留，旧集合始终
可核验。

用法（`set-verify` 成功退出码 0，失败 3）：

    python -m trusted_release --home store set-candidate \
        --name suite --set-version 2026.1 \
        --member libbase:1.0:libbase.bin:libbase.BUILD \
        --member app:1.0:app.bin:app.BUILD \
        --dep app:libbase \
        --policy-id set-standard --policy-version 1 \
        --require build=1 --require qa=1 --bundle set-candidate.json
    python -m trusted_release --home store set-approve \
        --candidate set-candidate.json --issuer build --output appr-build.json
    python -m trusted_release --home store set-finalize \
        --candidate set-candidate.json --approvals appr-build.json appr-qa.json \
        --bundle set-rel.json
    python -m trusted_release --home store set-verify \
        --bundle set-rel.json --member app:app.bin --member libbase:libbase.bin

离线接收者只需发布包、各成员文件与当前信任库；缺少某个成员文件时会
明确指出缺哪一项可信依据（`missing trusted basis: ... member
<product>`）。未提供 `--member` 时回退使用本地仓库中按内容寻址存储
的制品。完整演示见 `examples/release_set_demo.sh`（共享依赖、循环
依赖、部分批准、中断后接续、撤销重解释、旧集合核验）。

发布集合测试覆盖：共享依赖、循环依赖、缺失依赖声明拒绝、部分批准后
中断接续、替换成员/改依赖/改策略版本使旧批准失效、收集期间撤销
重解释、旧集合持续可核验、离线缺成员与成员被替换的明确定位。

## 测试

```bash
python -m pytest tests/ -q
```

覆盖：正常签发/离线验证、制品内容替换、构建说明替换、证明错配
（用另一文件的有效签名为当前文件背书）、签发者轮换后历史可查但
重验失败、证明过期、撤销使历史发布失效、CRL 版本累积与篡改失败
关闭、适用范围不匹配、发布中断不留可信索引。
