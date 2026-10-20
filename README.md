# keyref

keyref 是给人用的秘密管理器，也是给 AI agent 用的秘密代理。人在 iOS 上保管 API key、token、密码和笔记。Agent 通过 CLI **使用**这些秘密，但工具回传给模型的内容里**没有明文**。

典型用法：

```bash
keyref exec --env OPENAI_API_KEY=openai-prod -- \
  curl https://api.openai.com/v1/models
```

Agent 写下的是稳定引用 `openai-prod`，不是密钥本身。`keyref` 在子进程里注入真实的值，并把 stdout / stderr 里再次出现的秘密脱敏。

## 仓库里有什么

这是设计阶段。三个组件都还没有代码，只有目录和说明。

| 路径 | 内容 |
| --- | --- |
| [docs/design.md](docs/design.md) | 完整设计（中文） |
| [ios/](ios/) | iOS 管理端，Swift / SwiftUI，尚未实现 |
| [cli/](cli/) | Agent 用的 `keyref` CLI，Rust，尚未实现 |
| [server/](server/) | 密文同步服务，Cloudflare Workers + D1，尚未实现 |

本地现在没有可运行的服务。下一步是按 [docs/design.md](docs/design.md) 里的路线图做 Phase 0（手机上的本地保险库）。

## 已经定下的几件事

- 服务器只存密文。名称、描述、`ref` 和秘密值都在密文里。
- 主密钥留在 iOS 的 Secure Enclave 保护之下。CLI 只拿到被授权条目的条目密钥，拿不到主密钥。
- 占位符写成 `{{keyref:openai-prod}}`。更稳妥的注入方式是 `--env`、stdin 或额外的文件描述符，而不是把秘密放进进程参数。
- 同步层用 Cloudflare Workers + D1。个人使用和早期内测大多在免费额度内；当作正式服务，按每月 5 美元的 Workers Paid 底价规划。

设计里的取舍、威胁模型和还没拍板的问题都写在 [docs/design.md](docs/design.md)。
