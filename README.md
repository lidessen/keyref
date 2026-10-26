# keyref

keyref 是给人用的秘密管理器，也是给 AI agent 用的秘密代理。人在 iOS 上保管 API key、token、密码和笔记。Agent 通过 CLI **使用**这些秘密，但工具回传给模型的内容里**没有明文**。

典型用法：

```bash
keyref exec --env OPENAI_API_KEY=openai-prod -- \
  curl https://api.openai.com/v1/models
```

Agent 写下的是稳定引用 `openai-prod`，不是密钥本身。`keyref` 在子进程里注入真实的值，并把 stdout / stderr 里再次出现的秘密脱敏。

## 仓库里有什么

| 路径 | 内容 |
| --- | --- |
| [docs/design.md](docs/design.md) | 完整设计（中文） |
| [docs/protocol.md](docs/protocol.md) | 线协议契约：端点、请求/响应示例、签名誊本字节格式 |
| [server/](server/) | 密文同步服务，Go + SQLite，官方托管和自托管同一二进制 |
| [cli/](cli/) | Agent 用的 `keyref` CLI，Go（v0.4 起与服务器同语言） |
| [ios/](ios/) | iOS 管理端，Swift / SwiftUI，已实现 |
| [scripts/](scripts/) | 本地开发脚本：安装 CLI、起开发服务器、docker compose |

三端均已实现。server / cli / proto / tools 的 `go vet` + `go test` 与 CLI 端到端测试（对着真实拉起的服务器走通建库、配对、同步、exec）在 CI 门禁里（[.github/workflows/ci.yml](.github/workflows/ci.yml)）；iOS 的 KeyrefCore / KeyrefUI 测试在模拟器与 macOS 上本地运行（见 [ios/README.md](ios/README.md)），CI 暂无 iOS job。

## 本地开发

```bash
# 1. 起服务器（开发模式：plain HTTP、无配额），默认 127.0.0.1:8080
scripts/run-server.sh

# 2. 安装 CLI 到 PATH（默认 /usr/local/bin，可用 KEYREF_BIN_DIR 覆盖）
scripts/install-cli.sh

# 3. 或者用 docker compose 跑同一个服务器镜像
scripts/docker-up.sh      # 构建镜像并启动；scripts/docker-down.sh 停止
```

CLI 指向本地服务器：`KEYREF_SERVER=http://127.0.0.1:8080 keyref pair`。

## 已经定下的几件事

- 服务器只存密文。名称、描述、`ref` 和秘密值都在密文里。
- 主密钥留在 iOS 的 Secure Enclave 保护之下。CLI 只拿到被授权条目的条目密钥，拿不到主密钥。
- 占位符写成 `{{keyref:openai-prod}}`。更稳妥的注入方式是 `--env`、stdin 或额外的文件描述符，而不是把秘密放进进程参数。
- 同步层是一份 Go 服务器加嵌入式 SQLite。什么都不配置时，iOS 和 CLI 连官方托管；把服务器 URL 改成自己的地址就是自托管。托管按固定月租加硬配额来收费，避免免费用量把账单撑开。自托管免费。

设计里的取舍、威胁模型和还没拍板的问题都写在 [docs/design.md](docs/design.md)。
