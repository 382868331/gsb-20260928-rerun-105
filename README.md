# 软件制品可信发布系统（本地原型）

纯本地、纯标准库实现，不启用自动构建，不依赖任何云服务。制品内容、构建说明、
签发者关系分开保存，签名同时绑定制品实际内容（SHA-256）与声明。

## 存储布局（默认目录 .trusted）

- `objects/<digest>`：内容寻址的制品与构建说明，改名不影响身份，内容被替换必然得到新摘要。
- `manifests/register-<digest>.json`：登记记录（内容摘要、原始文件名、构建说明摘要）。
- `attestations/att-<digest>.json`：签名证明（声明 + 签发者签名）。
- `issuers/issuer-<id>.json`：受信签发者公钥关系。
- `revocations/revoked-<serial>.json`：撤销记录。
- `releases/release-<version>.json`：仅在全部校验通过后写入的可信版本记录。
- `keys/`：本地临时测试密钥（`*.pem` 已被 .gitignore 忽略）。

## 快速使用

```sh
go run ./cmd/trustedrelease keygen -name test-issuer
go run ./cmd/trustedrelease register -artifact app.bin -build build.json
go run ./cmd/trustedrelease attest -artifact app.bin -build build.json \
    -issuer test-issuer -key .trusted/keys/test-issuer.key -ttl 720h
go run ./cmd/trustedrelease verify -artifact app.bin -build build.json
go run ./cmd/trustedrelease release -artifact app.bin -build build.json -version v1.0.0
```

过期或撤销的证明无法通过验证，也无法发布为可信版本：

```sh
go run ./cmd/trustedrelease revoke -artifact app.bin -reason "incident"
```

改名后的同一文件仍可验证；内容被改动、证明缺失、过期、撤销均校验失败。

