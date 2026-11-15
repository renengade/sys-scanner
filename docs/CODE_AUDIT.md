# Code Audit — sys-scanner 1.2.2

审计日期：2026-11-15
范围：`main.go`、`internal/**`（正确性、健壮性、跨平台行为、确定性、死代码）
方法：人工审查 + `staticcheck`（Linux/Windows/Darwin）+ `errcheck` + `gosec`（Linux/Windows）+ `govulncheck` + 单元/集成测试

## 结论

上一轮安全审计之后，本轮聚焦正确性与工程质量。发现并修复了 6 类问题：

1. **去重输出顺序不确定**（中）
2. **Windows Store 中文厂商名可能乱码**（中，影响中文环境）
3. **App Paths 漏扫 32 位视图**（低，完整性）
4. **只读安装目录下汇总表直接失败**（低，健壮性）
5. **Windows 上按名称匹配 AI 工具时大小写敏感**（低）
6. **跨平台死代码**（低，维护性）

其余方面（HTML 转义、原子写入、子进程路径、并发模型、错误处理）未发现新问题。

## 修复明细

### 1. `merge.Deduplicate` 输出确定性

- 问题：最终排序只比较 `Name` 和 `Version`。当同一软件名/版本来自不同发布者（例如 `Same` + `Alpha Corp` 与 `Beta Corp`），或输入顺序因并发扫描/Go map 遍历而变化时，输出顺序可能不同。
- 影响：XLSX 汇总表 diff 可能误报新增/删除（同名同版本但顺序变化），资产采集端 diff 不稳定。
- 修复：排序加入 `Publisher`、`Source` 升级为决胜键；`ProgramSorter` 同步修改。
- 测试：`TestDeduplicate_DeterministicAcrossShuffles` 用 25 次轮转输入验证输出完全一致。

### 2. Windows Store 扫描的编码问题

- 问题：PowerShell 5.1 重定向 stdout 默认使用系统 ANSI 代码页，中文环境的 `Publisher`（如腾讯、微软中国）在 `ConvertTo-Json` 后会被按 GBK/936 编码写出，Go 按字节当 UTF-8 解析，产生乱码甚至 JSON 解析失败。
- 修复：命令前注入
  `[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;`
  并在解析前剥离可能出现的 UTF-8 BOM（`stripJSONBOM`，带单元测试）。
- 影响：`store` 来源记录的 publisher 对非 ASCII 更可靠。

### 3. App Paths 32 位视图

- 问题：只扫描 HKLM/HKCU 的 64 位视图，32 位程序在 `WOW6432Node` 下的 App Paths 不可见。
- 修复：增加 `registry.WOW64_32KEY` 视图；重复条目由既有去重逻辑合并。

### 4. 只读安装目录下的汇总表回退

- 问题：默认汇总表写在 exe 同级 `sys-scanner/`，若安装在 `Program Files` 等只读位置，更新失败直接告警。
- 修复：默认路径失败时回退到 `%TEMP%\sys-scanner\sys-scanner-summary.xlsx`（显式 `-summary-out` 不回退），与 HTML 报告的回退策略一致。

### 5. Windows 下 AI 工具名称匹配

- 问题：`prog.Name == signature binary` 的比较区分大小写；Windows 上 `OpenCode.exe` / `opencode.exe` 混用会导致漏判。
- 修复：`binaryNameEquals` 在 Windows 上使用 `EqualFold`（路径匹配已有同样处理）。

### 6. 死代码与跨平台构建噪声

- 移除：`classifier.hasProcess`（生产路径使用 `hasProcessIn`）、`windows.registrySourceName`、`startmenu.iShellLinkResolve`、未使用的 `kernel32` DLL 句柄、`macos.Scanner.scanPATH` 包装、`macos.sysProfilerEntry` 结构体。
- 将 Windows 专用 helper（`windowsRootDir`、`windowsSystemToolPath`、`includeStartMenu`）移入 `//go:build windows` 文件；macOS brew 拆分为可移植解析器 + darwin 命令执行文件。
- 结果：`staticcheck` 在 Linux/Windows/Darwin 三个目标上均为 0 findings；`errcheck` 为 0。

## 工具扫描记录

| 工具 | 范围 | 结果 |
|------|------|------|
| `staticcheck ./...` | Linux | 0 findings |
| `GOOS=windows staticcheck ./...` | Windows | 0 findings |
| `GOOS=darwin staticcheck ./...` | Darwin | 0 findings |
| `errcheck ./...` | 全部包 | 0 |
| `gosec -quiet ./...` / `GOOS=windows` | 安全静态分析 | 0 issues |
| `govulncheck ./...` | Go 漏洞库 | No vulnerabilities found |
| `go test ./...` | 全部包（含 Linux/Windows/macOS runner） | PASS |
| `go vet ./...` | 静态检查 | clean |

## 未修复 / 已接受的取舍

| 项 | 等级 | 说明 |
|----|------|------|
| `AmazonQ` 签名二进制名 `q` 可能过匹配 | 低 | 命中要求 `prog.Name == "q"` 且该名字在 PATH 上；误报可能性存在，但移除会降低检出率 |
| `-out` / `-summary-out` 可写任意本地路径 | 低 | CLI 预期能力，不做白名单 |
| 共享目录 XLSX 并发写 | 低 | 已在文档中提示顺序执行/合并 |
| XLSX 读取自身旧文件 | 低 | Excelize 已修复已知解析漏洞；文件权限 `0600` |
| 其他用户注册表配置单元 | 低 | 未扫描 `HKU`；需要管理员权限，暂不实现 |
| 便携软件 / 语言包（pip、npm 等） | 低 | 未纳入清单来源（见 README 已知限制） |

## 后续建议

1. 若未来新增平台扫描器，请实现 `DetectContext` 并保持 `Detect()` 兼容，避免 `runDetect` 的 goroutine 回退路径被触发。
2. 若引入更多 Windows PowerShell 数据源，统一使用 `getCmdAppxPackage` 的 UTF-8 前缀模式。
3. 继续在 CI 中保持 `staticcheck`（三平台）、`errcheck`、`gosec`、`govulncheck` 绿灯；新规则出现时先修代码，再考虑豁免注释。
