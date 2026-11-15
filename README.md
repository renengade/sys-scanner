# sys-scanner

> Endpoint software inventory and AI coding tool detection — portable, zero-install, cross-platform.

[English](#english) | [中文](#中文)

---

<a id="english"></a>
## English

### Overview

`sys-scanner` scans a workstation for installed applications, detects AI coding tools, and produces:

- an interactive **HTML report**;
- a cumulative **XLSX summary** that tracks every machine you run it on;
- optional machine-readable **JSON** / **CSV** for asset management systems.

It is a single static binary with no installer, no service, and no network access.

### Features

- Windows, macOS, and Linux support.
- 23 AI coding tools detected through 5 signal types.
- Windows/Microsoft built-in components filtered by default.
- Cumulative per-machine XLSX summary with add/remove tracking.
- Host identity in reports and inventory: hostname, IP, MAC.
- Human-readable local timestamps in reports and spreadsheets.
- Offline by design: nothing is uploaded.

### Platform coverage

| Platform | Program sources |
|----------|-----------------|
| Windows | Registry Uninstall entries (HKLM 64/32-bit + HKCU), App Paths, PATH, Microsoft Store/AppX, WSL AI-tool probe |
| macOS | `.app` bundles, Homebrew formulae/casks, `system_profiler`, PATH |
| Linux | `.desktop` files, dpkg/rpm/pacman/apk/snap/flatpak, `/opt/`, PATH |

### AI tools detected

- **Coding assistants:** OpenCode, Codex CLI, Claude Code, GitHub Copilot, Aider, Cline, Roo Code, Continue, Cody, Tabnine, Amazon Q Developer, Codeium, Augment Code, Hermes
- **AI editors / IDEs:** Cursor, Windsurf, Zed AI, PearAI, Trae
- **Local LLM runners:** Ollama, LM Studio, GPT4All, LocalAI

Detection uses binary names, config directories, VS Code extensions, running processes, and listening ports. A listening port alone is treated as weak evidence and never claims a tool is installed by itself.

### Download

Download the latest binary from [Releases](../../releases):

| File | Platform |
|------|----------|
| `sys-scanner-windows-amd64.exe` | Windows 10/11 x64 |
| `sys-scanner-linux-amd64` | Linux x86_64 (including WSL) |
| `sys-scanner-linux-arm64` | Linux ARM64 |
| `sys-scanner-darwin-amd64` | Intel Mac |
| `sys-scanner-darwin-arm64` | Apple Silicon Mac |

### Quick start

```bash
# Windows PowerShell
.\sys-scanner-windows-amd64.exe

# macOS / Linux
chmod +x ./sys-scanner-linux-amd64
./sys-scanner-linux-amd64
```

The HTML report opens automatically.

### Usage

```bash
# HTML report + XLSX summary (default)
sys-scanner

# Machine-readable JSON
sys-scanner -format json -out ./inventory.json -no-open

# CSV to stdout (for collectors)
sys-scanner -format csv -out -

# Include Windows/Microsoft built-ins for a full audit
sys-scanner -include-builtin

# Resolve Start Menu shortcuts (slower, mostly duplicates)
sys-scanner -lnk

# Custom output location
sys-scanner -out D:\Reports\report.html
```

| Flag | Default | Description |
|------|---------|-------------|
| `-format` | `html` | `html`, `json`, or `csv` |
| `-out` | `<exe dir>/sys-scanner` | Output path, directory, or `-` for stdout |
| `-no-open` | `false` | Do not open the HTML report |
| `-timeout` | `120s` | Overall scan timeout |
| `-include-builtin` | `false` | Include Windows/Microsoft built-in components |
| `-lnk` | `false` | Resolve Start Menu `.lnk` shortcuts (slower) |
| `-summary` | `true` | Maintain the cumulative per-machine summary XLSX |
| `-summary-out` | `<output dir>/sys-scanner-summary.xlsx` | Summary XLSX path or directory |
| `-version` | | Print version and exit |

### Outputs

By default everything is written next to the executable, under `sys-scanner/`:

```text
<exe dir>/sys-scanner/sys-scanner-report.html
<exe dir>/sys-scanner/sys-scanner-summary.xlsx
<exe dir>/sys-scanner/sys-scanner-inventory.json   # with -format json
<exe dir>/sys-scanner/sys-scanner-inventory.csv    # with -format csv
```

#### HTML report

- Program table with name, version, publisher, source, and full install location.
- AI-tool highlighting and an AI-only tab.
- Host, IP, MAC, platform, scan time, and duration in the header.
- Search and sorting, fully self-contained.

#### XLSX summary

A cumulative workbook written next to the HTML report:

```text
<exe dir>/sys-scanner/sys-scanner-summary.xlsx
```

- One row per program.
- Columns: machine ID, hostname, OS, architecture, IPs, MACs, scan time, scanner version, name, version, publisher, location, source, AI flags.
- `scan_time` is human-readable local time, e.g. `2026-11-15 18:00:00 CST`.
- Re-running on the same machine replaces that machine's rows and reports `+N added / -N removed / ~N updated`.
- Software version changes are updates, not add/remove.
- Unchanged runs leave the workbook untouched (no rewrite).
- Other machines accumulate in the same workbook.
- Corrupt or incompatible workbooks are moved to `.bak` and rebuilt.

#### JSON inventory

Schema-versioned (`schema_version: "1.1"`), suitable for a central collector:

```json
{
  "schema_version": "1.1",
  "scanner_version": "1.3.1",
  "generated_at": "2026-11-15T08:00:00Z",
  "generated_at_local": "2026-11-15 16:00:00 CST",
  "host": {
    "hostname": "ws-001",
    "os": "windows",
    "arch": "amd64",
    "ip_addresses": ["192.168.1.20"],
    "mac_addresses": ["aa:bb:cc:dd:ee:ff"]
  },
  "summary": { "program_count": 55, "ai_tool_count": 3 },
  "ai_tools": ["claude-code", "opencode", "ollama"],
  "programs": [],
  "programs_by_source": { "registry": 34, "store": 3, "PATH": 3 },
  "scan_duration_ms": 1300
}
```

See [docs/INVENTORY.md](docs/INVENTORY.md) for the full field reference and collection guidance.

#### CSV

A flat software table:

```text
name,version,publisher,location,source,is_ai_tool,ai_tool_name
```

### How the inventory is determined

`sys-scanner` reads each platform's standard software registration sources instead of crawling the whole filesystem.

**Windows**

- Uninstall registry keys: HKLM 64-bit, HKLM 32-bit, HKCU.
- App Paths under HKLM/HKCU.
- System and user PATH (allowlisted tools).
- Microsoft Store/AppX via PowerShell, with registry fallback.
- WSL AI-tool probe via `wsl.exe`.
- Default filters: `SystemComponent`, `NoRemove`, child patch entries, hotfixes, hidden ARP entries, Windows/Microsoft runtimes, inbox Store apps, System32 tools.
- Start Menu `.lnk` scanning is opt-in (`-lnk`).

**macOS**

- `.app` bundles and `Info.plist` metadata.
- Homebrew formulae and casks.
- `system_profiler SPApplicationsDataType`.
- PATH (allowlisted tools).

**Linux**

- Package managers: dpkg, rpm, pacman, apk, snap, flatpak.
- `.desktop` entries.
- `/opt/`.
- PATH (allowlisted tools).

**Merging**

Entries are normalized by name, stripped of version/architecture suffixes, grouped by publisher where appropriate, and deduplicated with a source priority (registry/system_profiler > package manager > Store > App Paths > `.desktop` > PATH).

### Build

Requires Go 1.26+.

```bash
make all      # all five binaries
make test     # go test ./...
make vet      # go vet ./...
```

Individual targets: `make windows`, `make linux-amd64`, `make linux-arm64`, `make macos-amd64`, `make macos-arm64`.

### Security

- The tool never opens a network connection.
- Scans are read-only.
- Reports, inventories, and summaries are written atomically with `0600` permissions where supported.
- Generated data contains hostnames, IP/MAC addresses, paths, and software names. Treat it as sensitive.
- Dependencies are pinned with `go.sum`; CI runs `go vet`, `gosec` and `govulncheck` (see [SECURITY.md](SECURITY.md) and [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md)).

### Limitations

- No universal registry exists for “all installed software”; portable apps, language packages (`pip`, `npm`, etc.), containers, and other users' per-user installs may not appear.
- Windows built-ins and runtimes are filtered by default; use `-include-builtin` for an audit view.
- Start Menu shortcuts are off by default; use `-lnk` to include them.
- WSL is fully inventoried only by running the Linux binary inside WSL.
- macOS binaries are unsigned; Gatekeeper may require right-click → Open.
- No 32-bit builds.

### Repository layout

```text
.
├── main.go
├── internal/
│   ├── classifier/       AI tool classification
│   ├── export/           JSON/CSV export
│   ├── hostinfo/         hostname/IP/MAC collection
│   ├── inventory/        inventory assembly
│   ├── merge/            deduplication/merging
│   ├── report/           HTML report + browser launcher
│   ├── scanner/          platform scanners (linux/macos/windows)
│   ├── signatures/       AI tool signature database
│   ├── summary/          cumulative XLSX workbook
│   └── types/            shared data models
├── docs/
│   ├── AUDIT.md          implementation audit
│   └── INVENTORY.md      JSON/XLSX schema and collection guide
├── Makefile
└── RELEASE.md
```

### License

[MIT](LICENSE)

---

<a id="中文"></a>
## 中文

### 概述

`sys-scanner` 用于清点终端电脑上已安装的软件、识别 AI 编程工具，并生成：

- 交互式 **HTML 报告**；
- 跨机器累积的 **XLSX 汇总表**；
- 供资产系统采集的 **JSON / CSV** 清单。

单个静态二进制，无需安装、无需常驻服务、不联网。

### 主要特性

- 支持 Windows、macOS、Linux。
- 通过 5 种信号识别 23 款 AI 编程工具。
- 默认过滤 Windows/Microsoft 自带组件。
- 汇总表按机器累积，自动统计新增/删除。
- 报告和清单包含主机名、IP、MAC。
- 报告和表格中的时间使用本地可读格式。
- 完全离线。

### 平台覆盖

| 平台 | 软件来源 |
|------|----------|
| Windows | 注册表卸载项（HKLM 64/32 位 + HKCU）、App Paths、PATH、Microsoft Store/AppX、WSL AI 工具探测 |
| macOS | `.app` 应用包、Homebrew、`system_profiler`、PATH |
| Linux | `.desktop`、dpkg/rpm/pacman/apk/snap/flatpak、`/opt/`、PATH |

### 可识别的 AI 工具

- **编程助手：** OpenCode、Codex CLI、Claude Code、GitHub Copilot、Aider、Cline、Roo Code、Continue、Cody、Tabnine、Amazon Q Developer、Codeium、Augment Code、Hermes
- **AI 编辑器 / IDE：** Cursor、Windsurf、Zed AI、PearAI、Trae
- **本地大模型运行器：** Ollama、LM Studio、GPT4All、LocalAI

### 下载

从 [Releases](../../releases) 下载对应二进制：

| 文件 | 平台 |
|------|------|
| `sys-scanner-windows-amd64.exe` | Windows 10/11 x64 |
| `sys-scanner-linux-amd64` | Linux x86_64（含 WSL） |
| `sys-scanner-linux-arm64` | Linux ARM64 |
| `sys-scanner-darwin-amd64` | Intel Mac |
| `sys-scanner-darwin-arm64` | Apple Silicon Mac |

### 快速开始

```bash
# Windows PowerShell
.\sys-scanner-windows-amd64.exe

# macOS / Linux
chmod +x ./sys-scanner-linux-amd64
./sys-scanner-linux-amd64
```

HTML 报告会自动打开。

### 使用说明

```bash
# 默认：HTML 报告 + XLSX 汇总表
sys-scanner

# JSON 清单
sys-scanner -format json -out ./inventory.json -no-open

# CSV 输出到标准输出
sys-scanner -format csv -out -

# 完整审计：保留 Windows/Microsoft 自带组件
sys-scanner -include-builtin

# 解析开始菜单快捷方式（较慢）
sys-scanner -lnk

# 自定义输出位置
sys-scanner -out D:\Reports\report.html
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-format` | `html` | `html`、`json` 或 `csv` |
| `-out` | `<exe 目录>/sys-scanner` | 输出路径、目录，或 `-` 表示标准输出 |
| `-no-open` | `false` | 不自动打开报告 |
| `-timeout` | `120s` | 整体扫描超时 |
| `-include-builtin` | `false` | 保留 Windows/Microsoft 自带组件 |
| `-lnk` | `false` | 解析开始菜单 `.lnk` 快捷方式 |
| `-summary` | `true` | 维护跨机器 XLSX 汇总表 |
| `-summary-out` | `<输出目录>/sys-scanner-summary.xlsx` | 汇总表路径或目录 |
| `-version` | | 打印版本后退出 |

### 输出位置

默认写入可执行文件所在目录下的 `sys-scanner/`：

```text
<exe 目录>/sys-scanner/sys-scanner-report.html
<exe 目录>/sys-scanner/sys-scanner-summary.xlsx
<exe 目录>/sys-scanner/sys-scanner-inventory.json
<exe 目录>/sys-scanner/sys-scanner-inventory.csv
```

#### XLSX 汇总表

- 每个软件一行。
- 包含机器 ID、主机名、系统、架构、IP、MAC、扫描时间、采集器版本、软件信息。
- `scan_time` 为本地可读时间，例如 `2026-11-15 18:00:00 CST`。
- 同一台机器重复运行会替换旧记录，并输出 `+N added / -N removed`。
- 软件版本变化不算新增/删除。
- 不同机器会持续累积。
- 损坏或表头不兼容的旧文件会自动改名为 `.bak`。

#### JSON 清单

`schema_version: "1.1"`，字段说明见 [docs/INVENTORY.md](docs/INVENTORY.md)。

#### CSV

```text
name,version,publisher,location,source,is_ai_tool,ai_tool_name
```

### 清单判断方式

- **Windows：** 注册表卸载项、App Paths、PATH、Store/AppX、WSL AI 工具探测；默认过滤系统组件、运行时和内置 Store 应用。
- **macOS：** `.app`、Homebrew、`system_profiler`、PATH。
- **Linux：** 包管理器、`.desktop`、`/opt/`、PATH。
- **合并：** 名称归一化、版本/架构后缀清理、按发布者分组、按来源优先级去重。

### 构建

需要 Go 1.26+：

```bash
make all      # 构建全部 5 个二进制
make test     # 运行测试
make vet      # 静态检查
```

单独构建：`make windows`、`make linux-amd64`、`make linux-arm64`、`make macos-amd64`、`make macos-arm64`。

### 安全

- 不联网。
- 只读扫描。
- 报告、清单和汇总表原子写入，支持 POSIX 的系统使用 `0600` 权限。
- 生成数据包含主机名、IP/MAC、路径和软件名称，请按敏感数据管理。
- 依赖由 `go.sum` 锁定；CI 会运行 `go vet`、`gosec` 和 `govulncheck`（见 [SECURITY.md](SECURITY.md) 与 [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md)）。

### 已知限制

- 没有“所有已安装软件”的统一登记表；便携软件、语言包（pip/npm 等）、容器、其他用户的安装可能无法覆盖。
- Windows 自带组件默认过滤，可用 `-include-builtin` 查看。
- 开始菜单 `.lnk` 默认不扫描，可用 `-lnk` 开启。
- WSL 内完整软件清单需要在 WSL 中运行 Linux 版。
- macOS 二进制未签名，可能需要在 Gatekeeper 中右键打开。
- 不提供 32 位版本。

### 许可证

[MIT](LICENSE)
