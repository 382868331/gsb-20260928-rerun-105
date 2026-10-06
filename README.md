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

## 发布集合（Release Collections）

一次发布常包含彼此依赖的多个制品。**发布集合**把一组明确的制品版本
连同它们之间的依赖声明一起固定进一份集合规格（spec），审批与验证都
覆盖集合整体，而不是分别批准后任意拼装：

- **整体批准**：批准签名绑定候选 digest，而候选 digest 覆盖集合规格
  （全部成员制品哈希 + 构建说明哈希 + 依赖声明）与完整策略版本。
  集合内替换任何一个制品、构建说明或依赖说明都会得到新候选，
  旧批准对新集合一律不再适用。
- **依赖图**：成员用 depends_on 声明对本集合内其他成员的版本钉扎；
  允许共享依赖（多个成员依赖同一成员）与循环依赖（A↔B），
  但任何指向集合外的依赖都会在结构校验时被拒绝。
- **部分批准与重新解释**：签发者可以先后各自批准，批准是可独立保存
  的文件。finalize 时按**当前**信任库与当前 CRL 重新解释每一份批准
  ——收集期间策略版本变化（批准绑定 policy_digest）或签发者被撤销，
  都会使相应批准不再计数；补齐可信批准后可接续 finalize。
- **原子进入可信目录**：集合记录先落盘为不可变文件，index.json 最后
  原子追加；finalize 失败或中断不会暴露半份集合，旧集合继续可核验。
- **离线核验与缺失定位**：接收者只需集合发布包、成员内容与当前信任库。
  collection-verify 逐项报告缺失的可信依据（哪个成员内容缺失、哪个
  角色批准不足、哪份批准因撤销/轮换不再计数），详见 checks.missing_trust。

```bash
python -m trusted_release --home store collection-candidate \
    --name platform --version 2026.10 \
    --member app:2.0:app.tar:APP.BUILD --member lib:1.3:lib.tar:LIB.BUILD \
    --dep app:2.0=lib:1.3 \
    --policy-id standard --policy-version 1 --require build=1 --require qa=1 \
    --bundle candidate.json
python -m trusted_release --home store collection-approve \
    --candidate candidate.json --issuer build --output build.json
python -m trusted_release --home store collection-finalize \
    --candidate candidate.json --approvals build.json qa.json --bundle rel.json
python -m trusted_release --home store collection-verify --bundle rel.json --json
python -m trusted_release --home store collection-list
```

完整演示（共享依赖、循环依赖、部分批准、撤销后重新解释、中断接续、
离线核验与缺失定位）见 `examples/demo_collection.sh`。

集合记录存储在 `registry/collections/<collection_release_id>.json`，
目录条目追加在 `index.json` 的 `collections` 列表中。

## 发布集合兼容升级组合选择（Upgrade Planning）

审批人员面对同一产品的多个候选制品版本时，不应按依赖遍历顺序贪心拼装。
兼容升级规划把整个集合视为一个全局约束问题：

- **共享依赖只有一份实际版本**：同一产品在候选组合中只能选择一个版本，
  所有依赖范围必须共同约束这份版本；两个目标要求互不相交流段时，
  完整目标集合无技术可行解，但可报告覆盖目标最多的局部方案。
- **互斥与循环依赖全局求解**：`conflicts_with` 在完整组合上检查；
  循环依赖按共同约束处理，A/B 任一遍历起点都得到相同结论。
- **双目标排序**：每个可行方案同时给出 `coverage_count` 与 `change_count`，
  调用方可比较覆盖目标最多与相对当前集合改动最少的方案。
- **预览分离两类结论**：`technical_options` 只表示版本范围、互斥与集合
  结构技术兼容；`publish_ready_options` 还要求当前签名、密钥状态、时间窗、
  CRL 与角色数量均通过验证。缺少批准的组合可预览但不能发布。
- **确认时重新验证**：确认接口会重新计算集合规格与候选 digest，
  并只提交绑定所选候选 digest 的批准；最终发布仍由 finalize 路径按当前
  信任库和 CRL 再验证一次。属于其他候选的批准不会计入新组合。
- **已发布集合不变**：如果预览选出的成员和策略与当前集合完全相同，
  选项标记为 `already_published`，确认会拒绝重复发布，原集合记录和索引保持原样。

核心 API：

```python
plan = publisher.preview_collection_upgrade(
    name="platform",
    version="2026.11",
    current_collection=old_record,
    policy=ReleasePolicy("standard", 1, {"build": 1, "qa": 1}),
    targets=[("app", "2.1")],
    candidates=[{
        "product": "app",
        "version": "2.1",
        "artifact_path": "app-2.1.tar",
        "build_spec_path": "APP.BUILD",
        "requires": [{"product": "lib", "specifier": ">=1.0,<2.0"}],
        "conflicts_with": [{"product": "plugin", "specifier": "<1.2"}],
    }],
    now=now,
)
record = publisher.confirm_collection_upgrade(
    plan,
    selection_id=plan["recommended"]["id"],
    approvals=approvals_for_selected_candidate,
    now=confirm_time,
)
```

候选也可以只提供已登记的 `artifact_digest` / `build_spec_digest` 与版本约束，
因此规划过程可完全离线进行。纯规划入口为
`trusted_release.upgrade.plan_compatible_upgrade()`；发布器入口额外负责构造确定性
候选、判断批准归属并执行最终发布校验。

## 发布集合版本对照报告（Collection Compare）

审批人员选择两个已发布集合，`collection-compare` 生成一份自包含、可离线
保存的对照报告（`trusted_release/compare.py`）：

- **制品内容变化**：新增 / 移除 / 替换了哪些成员（制品哈希与构建说明哈希
  分别标注），哪些成员保持不变；
- **依赖关系变化**：新增 / 移除的依赖边、两侧的共享依赖与循环依赖；
- **所需批准角色变化**：策略 id/版本与各角色所需批准数量的逐项差异；
- **批准逐项解释**：旧集合的每一份批准为何不再适用于新集合（批准绑定
  旧 `candidate_digest` / `policy_digest`），以及新集合每个角色还需
  补齐多少份绑定新候选的批准、旧集合中该角色的批准人是谁。

报告通过 `old` / `new` 两个摘要（`collection_release_id`、`spec_digest`、
`candidate_digest`、`policy_digest`、`record_id`）关联到两个集合，并自带
`report_id`。报告**只读**：不自动继承任何批准到新集合，也不改写两个已
发布集合的记录；生成前后两个集合均可独立核验。

```bash
python -m trusted_release --home store collection-compare \
    --old rel-v1.json --new rel-v2.json --output compare-report.json
```

`--old` / `--new` 接受发布包路径或 `collection_release_id`（从仓库读取）。
完整演示（共享依赖、循环依赖、单个制品替换）见
`examples/demo_collection_compare.sh`。


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
