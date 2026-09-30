# 软件制品可信发布系统（trusted-release）

纯 Python 标准库实现的**离线**软件制品可信发布工具链，覆盖四个环节：

1. **制品登记**：制品按 SHA-256 内容寻址入库，清单同时钉住制品与构建说明的摘要；
2. **构建说明绑定**：构建说明的摘要与制品摘要一起写入被签名的证明（attestation）；
3. **签发**：用签发者当前生效的 Ed25519 密钥对证明签名（Ed25519 按 RFC 8032 纯 Python 实现，可与 OpenSSL 互验）；
4. **离线验证**：仅凭签名发布包、制品文件、构建说明文件与本地信任资料即可验证，无需联网。

## 验证同时覆盖三件事

验证不是“找到一份能验过的签名”就算通过，而是在一次检查中同时证明：

| 维度 | 检查内容 |
| --- | --- |
| **内容** | 当前提供的制品文件哈希 == 签名的 `artifact_digest`；当前构建说明哈希 == 签名的 `build_spec_digest`。文件被替换即失败（`content mismatch` / `build spec mismatch`）。 |
| **签发者** | 签名能由证明中具名签发者（`issuer_id` + `key_version`）在**当前**信任库中的公钥验过；密钥状态、有效期窗口、当前撤销清单全部检查。 |
| **适用范围** | 密钥声明的 `scope`（`*` 或 `product:<名称>`）覆盖被签产品，且证明里的 scope 与密钥 scope 一致；可选 `expected_product` 再核对产品名。 |

此外会核对发布记录内嵌证明的 `release_id`/摘要与记录本身一致，防止把 A 文件的签名/证明挪用到 B 文件（mix-and-match）。证明内的过期时间、scope、签发者等字段都在签名覆盖范围内，篡改即导致 `signature verification failed`。

## 密钥轮换、过期与撤销资料版本

- **轮换**：`key-create` 对同一签发者再发一把密钥时，旧密钥自动变为 `rotated`，新密钥为 `active` 并用其签发新版本。历史发布记录与密钥历史始终可查看；默认策略下用旧（已轮换）密钥签发的历史发布**重新验证不再通过**（`not currently trusted`），仅当显式给出当前信任条件 `trust_rotated=True` 时才放行。
- **证明过期**：发布时写入 `not_before`/`expires_at`（默认 365 天），过期后验证报 `attestation expired`。密钥本身也支持 `valid_from`/`valid_to` 窗口。
- **撤销资料（CRL）版本管理**：撤销清单由专门的撤销签发者密钥签名，存为不可变快照 `crl/versions/000001.json ...`，`current.json` 指向当前版本；每次签发都是包含全部撤销项的新快照，旧快照保留可查。重新验证**只看当前快照**；当前快照签名或版本指针校验失败时**失败即关闭**（fail closed），不会放行。

## 发布中断不污染可信索引

发布顺序固定为：

1. 登记制品并绑定构建说明（读不到文件/内容异常立即失败）；
2. 用当前 active 密钥构造并签名证明（临时/损坏签发材料在此失败，例如 31 字节非法种子）；
3. **最后一步**才把发布写入不可变记录文件并原子更新 `index.json`。

因此任何失败或中断都不会在索引中留下可被当成可信版本的条目。

## 存储布局

```
<home>/registry/artifacts/sha256/<xx>/<hex>   # 内容寻址的制品/构建说明
<home>/registry/manifests/sha256_<hex>.json   # 制品+构建说明绑定清单
<home>/registry/releases/<release_id>.json    # 不可变签名发布记录
<home>/registry/index.json                    # 可信目录（原子更新）
<home>/issuers/keys.json                      # 版本化公钥与状态/scope/窗口
<home>/issuers/private/<issuer>.v<n>.key      # 32 字节 Ed25519 种子（0600，已 gitignore）
<home>/crl/versions/000001.json               # 已签名不可变撤销快照
<home>/crl/current.json                       # 当前快照指针
```

## CLI 用法

```bash
python3 -m trusted_release --home store init
python3 -m trusted_release --home store key-create --issuer build-team --scope product:widget
python3 -m trusted_release --home store key-create --issuer security-office --scope '*'

python3 -m trusted_release --home store publish \
  --artifact widget-1.0.tar.gz --build-spec BUILD.md \
  --product widget --version 1.0 --issuer build-team --bundle rel.json

# 离线验证（bundle 可拷贝到无网络环境；同时提供当前的制品与构建说明）
python3 -m trusted_release --home store verify \
  --bundle rel.json --artifact widget-1.0.tar.gz --build-spec BUILD.md

# 轮换 / 撤销 / 查看历史
python3 -m trusted_release --home store key-create --issuer build-team --scope product:widget
python3 -m trusted_release --home store revoke --crl-issuer security-office \
  --issuer build-team --key-versions 1 --reason compromise
python3 -m trusted_release --home store list
python3 -m trusted_release --home store crl-list
```

验证成功退出码为 0，不可信为 3；`verify --json` 输出各项检查明细。

## Python API

```python
from trusted_release import (
    IssuerKeyStore, Publisher, Registry, RevocationList,
    TrustPolicy, Verifier,
)

keys = IssuerKeyStore("issuers"); keys.create_key("build-team", scope="product:widget", now=NOW)
record = Publisher(Registry("registry"), keys).publish(
    artifact_path="widget.tar.gz", build_spec_path="BUILD.md",
    product="widget", version="1.0", issuer_id="build-team", now=NOW)
result = Verifier(keys, RevocationList("crl")).verify_release(
    record, artifact_path="widget.tar.gz", build_spec_path="BUILD.md", now=NOW)
assert result.ok  # result.checks 给出 content/signer/scope 逐项结果
```

## 测试

```bash
python3 -m pytest -q
```

测试包含 RFC 8032 Ed25519 标准向量（并与 OpenSSL 互验）、内容替换、构建说明替换、
证明错配/挪用、轮换后历史发布不可重新验证、过期、撤销与 CRL 版本累积、scope 不匹配、
CRL 被篡改后 fail-closed，以及签发失败时索引不新增条目。
