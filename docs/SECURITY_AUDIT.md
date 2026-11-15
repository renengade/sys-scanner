# Security Audit — sys-scanner 1.2.0

审计日期：2026-11-15（对应版本 1.2.1）
范围：`main.go`、`internal/**`、构建脚本与依赖
方法：人工代码审查 + `govulncheck` + `gosec`（Linux/Darwin 与 Windows build tag）+ `go vet` + 跨平台测试

## 结论

未发现可被远程利用的漏洞。该工具是本地 CLI、只读扫描、不联网，主要风险集中在

1. 生成文件包含主机名 / IP / MAC / 路径等敏感信息；
2. Windows 子进程调用的路径解析；
3. 生成文件的可读性与覆盖行为。

以下问题均已在本版本处理。

## 已实施的安全控制

### 数据面

| 控制 | 说明 |
|------|------|
| 不联网 | 代码中没有 HTTP 客户端/服务端；唯一的 socket 调用是 `classifier` 对 `127.0.0.1` 的本地端口探测 |
| 只读扫描 | 所有扫描源只读取注册表、目录、包管理器输出；不执行扫描目标中的任何文件 |
| 敏感输出保护 | HTML/XLSX/JSON/CSV 通过临时文件 + `rename` 原子写入；文件权限 `0600`，目录 `0700` |
| 无可预测临时文件 | 所有临时文件使用 `os.CreateTemp`，不会使用可预测的 `/tmp/sys-scanner-report.html` 覆盖共享路径 |

### 注入面

| 风险 | 处理方式 |
|------|----------|
| HTML 注入（XSS） | `ProgramView` 全部为普通字符串，`html/template` 在渲染时做上下文自动转义；报告中没有 `eval`、`new Function`、`innerHTML`，也没有外部资源 |
| Excel 公式注入 | `export.CSV` 对 `=`、`+`、`-`、`@`、TAB、CR 开头的值加前导 `'`；XLSX 使用 Excelize `SetCellStr` 写入字符串单元格，并显式调用 `removeFormula`，即使软件名以 `=` 开头也不会被解释为公式 |
| 命令注入 | WSL 探测脚本由静态签名数据库生成，不含用户输入；Store 扫描的 PowerShell 命令为固定命令；报告打开不再经过 `cmd.exe`（旧版 `%q` 路径问题已修复） |
| Windows 子进程劫持 | `powershell.exe`、`wsl.exe`、`rundll32.exe`、`tasklist.exe` 全部改为 `%SystemRoot%\System32` 下的绝对路径，避免被用户可写的 PATH 目录或当前目录替换 |
| 当前目录可执行文件劫持 | Go `exec` 默认对当前目录命中返回 `ErrDot`，不会静默执行；系统工具已改为绝对路径，双重防护 |
| 路径遍历 | `.desktop` 扫描来自固定目录列表；XLSX/报告输出路径来自用户 `-out`，这是本地 CLI 的预期行为 |

### 依赖

| 依赖 | 版本 | 说明 |
|------|------|------|
| `github.com/xuri/excelize/v2` | v2.11.1 | 修复 `govulncheck` 报告的 11 个 Excelize 漏洞（越界、panic、OOM 等） |
| `golang.org/x/crypto` | v0.59.0 | 升级 |
| `golang.org/x/net` | v0.62.0 | 升级 |
| `golang.org/x/text` | v0.44.0 | 升级 |
| `golang.org/x/sys` | v0.50.0 | 升级 |
| `howett.net/plist` | v1.0.1 | 仅 macOS 构建使用，`govulncheck` 无命中 |

供应链控制：

- `go.sum` 锁定哈希，`go mod verify` 通过；
- CI 中运行 `gosec` 与 `govulncheck`（`.github/workflows/security.yml`）；
- 依赖数量少，均为 Go 生态常用库。

## 扫描结果

| 工具 | 范围 | 结果 |
|------|------|------|
| `govulncheck ./...` | Go 漏洞数据库 | **No vulnerabilities found** |
| `gosec -quiet ./...` | Linux/Darwin build tag | **0 issues** |
| `GOOS=windows gosec -quiet ./...` | Windows build tag | **0 issues**（COM `unsafe` 调用与 HRESULT 位测试已标注/消除） |
| `go vet ./...` Linux/Windows/macOS ARM | 静态检查 | clean |
| `go test ./...` Linux/Windows/macOS runner | 单元测试 | PASS |

`gosec` 说明：

- `internal/scanner/windows/startmenu.go` 的 `unsafe` 调用用于 COM vtable 调用（IShellLink/IPersistFile），是该互操作方式的固有写法；指针仅指向本函数局部变量，未处理外部输入，已使用 `#nosec G103` 标注。
- `succeeded(hr)` 改为直接测试 HRESULT 的 31 位符号位，消除 `uintptr -> int32` 缩窄转换（G115）。

## 接受的风险

| 风险 | 等级 | 说明 |
|------|------|------|
| `-out` / `-summary-out` 可写任意本地路径 | 低 | 这是 CLI 的预期能力；运行者是本机用户，因此可写其可写的任何路径。不要以高权限账户运行 |
| 生成的汇总/报告包含主机敏感信息 | 中 | 文件本身 `0600`，但内容一旦共享（例如共享目录中的 `sys-scanner-summary.xlsx`）即脱离控制；建议集中采集时走内部系统 |
| 共享目录汇总表并发写入 | 低 | 多台机器同时写同一 XLSX 可能互相覆盖；建议顺序执行或各自生成后合并 |
| XLSX 读取自身文件 | 低 | `summary.Update` 会读取旧汇总表；若该文件被第三方替换，存在解析恶意 XLSX 的风险（本地攻击者已具备同权限）。Excelize 已修复已知的解析类漏洞 |
| 用户 PATH 中存在可写目录 | 低 | Linux/Darwin 的 `ps`、浏览器 launcher 仍按 PATH 查找；攻击者需要已能修改当前用户的 PATH，风险自限 |
| macOS 二进制未签名 | 低 | Gatekeeper 会提示；属分发签名问题，不是代码漏洞 |

## 建议

1. **不要把生成的 `sys-scanner-summary.xlsx` / HTML 报告放在公共可写目录长期保存**；集中采集后从端点删除。
2. 如果把汇总表放在共享目录，建议改为每台机器写本地文件，再由采集服务合并。
3. 后续升级依赖时运行：
   ```bash
   go run golang.org/x/vuln/cmd/govulncheck@latest ./...
   go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...
   GOOS=windows go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...
   ```
4. 如果未来把工具做成服务或计划任务，请避免以 SYSTEM/管理员运行，并对输出目录使用 ACL 限制。

## 复现扫描

```bash
# 漏洞扫描
go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# 静态安全分析（Linux/Darwin）
go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...

# 静态安全分析（Windows build tag）
GOOS=windows go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...

# 常规静态检查
go vet ./...
go test ./...
```
