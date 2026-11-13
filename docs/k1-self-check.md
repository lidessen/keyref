# K1 前的项目健康自查

- 项目 / 日期 / 检查人：keyref / 2026-11-14 / keyref 项目窗。
- 复核对象：S1 `0047831`、S2 `9eca165`；修复提交 `acb0aba`，分支 `fix/s2-review`。代码已本地提交；本页与 K1 计划属于随后的文档提交。未推送。
- 范围：lib/CLI 及直接调用的执行引擎。未修改 iOS、Android、server 或协议；没有读取真实 shell 凭证文件、使用真实 provider key 或启动 Workcells。
- 本页保留 S1/S2 当时的自查结论；之后 `import-env` 的实现与限制见 [K1 计划](k1.md) 和 [交接记录](handoff.md)。

## 1. 门禁与验证

| 检查 | 命令或范围 | 结果 / 证据 |
| --- | --- | --- |
| 现有 Go 门禁 | `go vet` / `go test -C <module> ./...`，module 为 server、cli、proto、tools/vectordump | 全部通过；无跳过或新增门禁 |
| 独立构建 | `GOWORK=off go build -C <module> ./...`，module 为 cli、server、tools/vectordump | 全部通过 |
| 并发 | `go test -C cli -race ./local ./cmd/keyref ./internal/exec` | 全部通过 |
| 完整 CLI e2e | `go test -C cli -tags=e2e -count=1 ./e2e` | macOS 212.436s；Linux `golang:1.26` 容器 228.544s；最后帮助文案另通过 CLI vet/test/build |
| 独立复核 | 两位 fresh-context reviewer 分别读取 S1/S2 实际提交 | S1 报告分块 fuzz/pty 实测通过；S2 返回具体缺陷，按下表处理。修复由本窗口回归验证，未宣称二次独立验收 |

原始执行日志保留在本会话的三个完成任务中：`b1ke4699c`（Go 门禁与 race）、`b0upct4rc`（macOS）、`bvlcfj06l`（Linux）；提交记录及可重跑用例在仓库中，不要求读者使用临时路径。

## 2. 复核发现与处置

| 级别 / 项目 | 处置与证据 | Owner / 复查 |
| --- | --- | --- |
| P1 URL userinfo 绕过主机检查 | 已修复：按完整 URL 的 Hostname 匹配，坏 URL 拒绝且不回显原文；`TestAllowedHostsURLAuthority`、`TestLocalAllowedHostsChecksArgv` 覆盖拒绝前不启动子进程 | keyref / 本次已复验 |
| P1 旧库迁移语义与并发 | 已修复：Stat 不再写入虚构大小/时间；Use 按密文条件回填；首开迁移串行；`migration_test.go` 覆盖首开、替换/删除、历史降级行及写入上限 | keyref / 本次已复验 |
| P2 meta 校验不对称 | 已修复：读写共用空串/NUL 校验；重复白名单项本来就是允许的冗余项，不是策略放宽 | keyref / 本次已复验 |
| P2 S1 失败输入未擦除、Write 失败缺回归 | 已修复：拒绝尺寸/读错误清零；读错误不透传输入；补直接 Write 失败且只调用一次 OnFail 的测试 | keyref / 本次已复验 |
| P1 local reveal 缺控制终端确认 | 未关闭；显式 `get --reveal` 仍可绕过设计中的人工确认。K1 注入不使用该通道；在 K1 里程碑内补设计 §17.4 的确认及无 tty 拒绝 | keyref / K1 发布前 |
| P2 终端读取自动化覆盖不足 | 本次 reviewer 做了 pty 实测，CI 尚缺终端输入/信号恢复的自动回归；不把手工探针当常驻门禁 | keyref / 下一 lib/CLI 切片复查 |

## 3. 腐化信号

修正了 CLI help 仍写“list 仅 paired”及本地固定 deny list 的漂移。没有削弱失败断言或通过静默重试掩盖失败。原项目地图把“核心已有功能可用”扩成了“S1/S2 全部收口”，现改为有边界的健康判断。S1 的 `window` 死状态、trim 碰撞标签歧义是 P2 清理项；相同输出可能来自多个 ref，当前按 ref 排序确定替换标签，Count 是总数，不能据此断言审计已错误归属到某条目。

## 4. 安全与边界

所有新增用例使用合成值；协调回复仅含 ref、命令、提交与结果。主机策略是 argv 检查，不约束 Neowind 配置内 endpoint、重定向或文件输出。本地空 `allowCommands` 保留内置拒绝名单；这不是对抗性隔离。本次自查时项目级授权、本地审计与 `import-env` 尚未交付，不能把 source 名或 ref 前缀声称为隔离。此轮无新依赖；全仓供应链审计不在范围内。

## 5. 声明与证据

已验证的是 Keyref 加密 meta、迁移、命令策略、注入/脱敏的现有门禁及新增负例。Neowind 已有 `api_key_env` 消费代码，本窗口仅核对了源码，尚未做真实 Neowind 产物的 provider 合成 key 联调和落盘扫描。真实 shell 格式覆盖、导入幂等/原子性、未授权项目拒绝均仍属于 K1 后续验收条件。iOS/Android 本轮未运行，范围未触及。

## 6. 结论

**继续第一切片的合成 key 联调；K1 整体验收保留。** 本轮确认的主机检查与迁移问题已修复；未发现真实凭证已泄露或数据损坏的证据。若后续发现值进入日志/回执、未经授权解密、迁移丢数据或必要门禁失效，立即停止功能扩展并修复。第一切片无需总部追加决定；不以注入可用替代本地 reveal 确认、审计、项目授权的验收。

相关入口：[K1 计划](k1.md)、[交接记录](handoff.md)、[项目地图](../PROJECT-MAP.md)。
