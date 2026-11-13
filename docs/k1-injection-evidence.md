# K1 注入验收记录

日期：2026-11-14。合同：[K1](k1.md)。本页分别记录 Keyref 进程注入与 Neowind 真实消费，只有两侧证据齐备才能关闭最小联调；它不代表完整 K1（导入、审计、项目授权）完成。

## Keyref 一侧

用例：[provider_env_test.go](../cli/e2e/provider_env_test.go)，消费者为 [测试夹具](../cli/e2e/testdata/helper/provider.go)，不是 Neowind。沿用现有 e2e 构建真实 Keyref CLI；临时 vault、主密钥和 provider 值均在测试时生成，不依赖 OS 中已有凭证，不读真实 shell 配置，也不访问真实 provider。

```sh
go test -C cli -tags=e2e -run '^TestProviderEnvironmentContract$' -count=1 -v ./e2e
```

| 场景 | 必须成立的断言 | 定向结果 |
| --- | --- | --- |
| JEV_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY | 回环接收端收到一次正确 Authorization header；请求正文不含值；注入覆盖父环境同名干扰值 | 3/3 通过 |
| 两条输出流 | 测试消费者故意在 stdout 写原值、stderr 写 base64；Keyref 均替换为 ref 标记，扫描无原值及常见编码 | 通过 |
| 环境过滤 | 子进程只收到显式传递的配置/状态路径与注入值；主密钥、Keyref 私有路径变量、其他 provider 凭证未被继承 | 通过 |
| 缺失 ref | 退出 11，没有子进程启动标记，没有 provider 请求 | 通过 |
| 锁定 vault | 退出 12，没有子进程启动标记，没有 provider 请求 | 通过 |
| 错误消费者 | 退出 10，没有子进程启动标记，没有 provider 请求 | 通过 |
| metadata / 文件 | get/list 不含值；隔离 vault、keyring、config/state 目录扫描无原值及常见编码 | 通过 |

定向运行六个子用例全部通过（2.691s，含构建/套件初始化）。完整 e2e：macOS 212.936s、Linux `golang:1.26` 容器 228.796s，六个子用例在两边均为 pass；原始 JSON 测试事件分别保留在 `out/k1/macos-e2e.jsonl` 与 `out/k1/linux-e2e.jsonl`（本机忽略产物，非凭证记录）。现有四模块 vet/test、GOWORK=off 独立构建及 e2e vet 也全部通过。没有新增依赖或修改生产执行路径。

## Neowind 一侧

已通过本机消息联系 Neowind 项目窗，在其停机回执切片的安全点对接；不占用其活动工作区或替其修改消费者代码。已交付可执行文件 `out/k1/keyref`，生产代码基线 `7979b0f`（执行修复在 `acb0aba`），SHA-256 为 `c3c7541588e954c10263da791aa75f99d8e6b80b5f9a99c30817c94d8665fe7c`。这是二进制 hash，不是凭证 hash。

**当前状态：权限阻塞，消费者验收未运行。** 2026-11-14，Neowind 项目窗回报：其会话的自动审批拒绝执行仓库外的固定版本 `out/k1/keyref`，连 `exec --help` 也被拒绝，理由是该二进制缺少该会话内的明确执行授权。此处记录的是对方的拒绝回报，不是 Keyref 自测失败。没有通过其他会话、工具、复制路径或测试包装重放被拒绝的执行；Neowind 继续原有授权下的回执切片。恢复条件是在 Neowind 会话自身完成该产物、合成 key 与回环检查范围的执行授权。

授权解决后，仍需绑定真实 Neowind 修订与产物，使用内存生成的合成 key，经 Keyref 启动真实命令，再核对认证 header，并扫描 stdout/stderr、日志、回执、计划和状态文件。回执仅保存路径、产物版本、布尔值、计数和退出码，不保存值或其 hash。Keyref helper 的结果不替代这份证据；最小联调保持未完成。

## 边界

`--allow-command` 是命令名字白名单；`--allow-host` 无法约束 Neowind 配置中的 endpoint。本次回环夹具只验证凭证传递与输出处理，不证明网络沙箱、项目身份隔离或真实 App e2e。真实 key 没有参与本轮，Workcells 不参与执行。本地 reveal 确认、审计与项目授权仍按 [自查](k1-self-check.md) 跟踪。
