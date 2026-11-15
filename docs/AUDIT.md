# sys-scanner 审查报告

审查日期：2026-11-15

审查目标：确认程序清单是否完整、是否有可修复缺陷，并补齐“终端电脑已安装软件”的采集能力。

## 结论

原有实现的核心扫描框架可用，但存在一个**明显的软件清单遗漏**（Linux Arch 系主机只报告 28 个程序，实际安装 259 个包）、一个**确定的 AI 工具误报**（本机仅因 8080 端口监听就报告 LocalAI）、以及缺少结构化输出的问题。以下问题已在本次修改中修复。

## 已修复

| 级别 | 问题 | 位置 | 修复 |
|------|------|------|------|
| 高 | Linux 只支持 dpkg/rpm/snap/flatpak，Arch/Alpine 主机几乎扫描不到已安装软件 | `internal/scanner/linux/packages.go` | 增加 `pacman -Q`、`apk info`。本机实测程序数从 28 提升到 273（其中 259 个包） |
| 高 | 只要本机有服务监听 8080 就误报 LocalAI | `internal/classifier/classifier.go` | 仅端口信号不再合成工具条目；必须有配置目录/扩展/进程等身份信号 |
| 高 | 扫描超时直接丢弃全部结果 | `main.go`、三个平台 scanner | 增加 `DetectContext`，在来源之间检查取消并返回部分结果 |
| 高 | Windows 报告生成成功但浏览器提示“找不到文件” | `internal/report/browser_windows.go` | `%q` 会把路径反斜杠转义成 `C:\\Users\\...`；改用 `rundll32 url.dll,FileProtocolHandler` 直接传路径 |
| 高 | 从 WSL 启动 Windows 版时 WSL 探测全部失败并输出 WARN | `internal/scanner/windows/wsl.go` | `wsl.exe` 使用 Windows 本地工作目录；探测脚本不再使用引号和 `$变量`，并显式以 `true` 结尾 |
| 高 | 报告写入 `/tmp` 且权限 0644，同机其他用户可读 | `internal/report/generator.go` | 临时文件 + `0600` + 原子替换 |
| — | 脚本清单（已在 1.2.0 取消） | 已移除 `internal/scanner/scripts` | 按需求移除脚本/自动化文件扫描，报告、JSON、CSV、汇总表只保留软件 |
| 中 | 报告默认写入系统临时目录，不便于随工具分发/收集 | `main.go`、`internal/report` | 默认写入 `<exe 目录>/sys-scanner/`；显式 `-out` 仍可覆盖 |
| 中 | 报告缺少主机 IP/MAC | 新增 `internal/hostinfo` | 报告头部和 JSON `host` 增加主机名、IP、MAC；自动跳过虚拟/容器/VPN 网卡 |
| 中 | 缺少跨机器的软件汇总视图 | 新增 `internal/summary` | 输出真正的 XLSX 到报告同目录；同机器替换、异机器追加；统计新增/删除；时间使用本地可读格式 |
| 中 | Windows 清单混入大量系统自带组件和 Store 内置应用 | `internal/scanner/windows/helpers.go`、`store.go` | 默认过滤 Windows/Microsoft 运行时、System32 工具、Store inbox 应用；`-include-builtin` 可保留 |
| 中 | 开始菜单 `.lnk` 与注册表重复且解析慢 | `internal/scanner/windows/windows.go` | 默认关闭 `.lnk` 扫描；`SYS_SCANNER_SCAN_LNK=1` 可开启 |
| 中 | Windows 各扫描源串行执行，耗时叠加 | `internal/scanner/windows/windows.go` | 各来源并发执行、结果按固定顺序合并；热缓存实测约 1.3s |
| 中 | 只能输出 HTML，无法接入资产系统 | 新增 `internal/export`、`internal/inventory` | `-format json/csv`、`-out`、`-out -`，JSON 带 schema 版本 |
| 中 | 进程信号全文子串匹配，`hermes-agent` 会命中 `hermes` | `internal/classifier/classifier.go` | 按进程行/镜像名锚定匹配 |
| 中 | 每个 AI 工具各执行一次进程枚举、各读一次扩展目录 | `internal/classifier/classifier.go` | 每次扫描只执行一次 `tasklist`/`ps`，扩展目录只读一次 |
| 中 | `sourcePriority` 缺少 store/apppaths/homebrew/wsl/opt，合并时可能选错记录 | `internal/merge/dedup.go` | 补齐来源优先级 |
| 中 | `-out -` 时进度信息混入 stdout，破坏 JSON/CSV | `main.go` | 进度日志改到 stderr，stdout 只输出数据 |
| 中 | `go build ./...`/`go test ./...` 在 Linux/Windows 上被 macOS 的 plist 依赖卡住 | `internal/scanner/macos/*` | 为 macOS 专属文件加 build tag，拆分可移植测试 |
| 低 | Makefile 目标没有源文件依赖，改代码后不会重新构建 | `Makefile` | 增加源文件依赖、`test`、`vet`、版本注入 |
| 低 | README 写 Go 1.22、22 款 AI 工具，与实际不符 | `README.md` | 改为 Go 1.25、23 款，并补充软件清单和导出说明 |
| 低 | dist 中 darwin 二进制无执行权限 | `dist/` | `chmod +x` |
| 低 | 缺少 JSON 字段说明和集中采集说明 | `docs/INVENTORY.md` | 新增 schema 与部署文档 |

## 仍未处理 / 建议后续

| 级别 | 事项 | 说明 |
|------|------|------|
| 中 | macOS 二进制未重新构建 | 本机离线且模块缓存中没有 `howett.net/plist`。需在有网络环境执行 `make macos`，当前 `dist/sys-scanner-darwin-*` 仍是 1.0.0 |
| 中 | 外部命令中的取消不够细 | `system_profiler`、WSL 多发行版探测、包管理器命令只在来源之间检查取消，单条命令仍依赖各自超时 |
| 低 | Linux 包管理器失败被静默跳过 | `scanPackages` 不返回错误；建议把每个管理器的失败计入 `errors_by_source` 并在 JSON 中体现 |
| 低 | 没有二进制签名校验 | 清单只做发现，不验证 Authenticode/notarization；如需合规基线，应增加签名校验 |
| 低 | 同名不同厂商的合并边界 | 去重仍基于名称 + 发布者启发式，极端情况下可能合并两个不同产品 |
| 低 | 未签名二进制 | Windows SmartScreen、macOS Gatekeeper 会提示；发布前应签名/公证 |

## 验证记录

```text
go test ./...                          PASS
go vet ./...                           PASS
GOOS=windows go vet ./...              PASS
GOOS=windows go build .                PASS
GOOS=linux GOARCH=arm64 go build .     PASS
./sys-scanner -format json -out -      stdout 为合法 JSON
./sys-scanner -format csv -out -       stdout 为合法 CSV
```

说明：受限于当前环境无外网、无 `howett.net/plist` 模块缓存，macOS 目标的交叉编译未能在本机执行；macOS 专属代码已通过 build tag 隔离，不影响 Linux/Windows 构建。

## 采集建议

- 软件清单：Windows 注册表 + Store + App Paths + 开始菜单；macOS `.app` + Homebrew + system_profiler；Linux 包管理器 + `.desktop` + `/opt` + PATH。
- 集中采集：使用 `-format json -out -` 或输出到受保护目录，由现有资产采集代理上传；程序本身保持离线。
