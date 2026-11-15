# 终端软件清单（Inventory）

sys-scanner 的 JSON 输出用于把终端电脑的软件和 AI 工具清点结果汇总到资产管理系统。文档对应 `schema_version: "1.1"`。

## 生成清单

```bash
sys-scanner -format json -out ./inventory.json -no-open
```

- `-format json`：输出机器可读清单。
- `-out -`：写到标准输出，便于管道或采集代理直接读取。
- 默认输出到 `<可执行文件目录>/sys-scanner/`。

文件在支持 POSIX 权限的系统上以 `0600` 权限原子写入；清单中包含主机名、IP、MAC 和文件路径，应按敏感数据管理。

## 顶层结构

```json
{
  "schema_version": "1.1",
  "scanner_version": "1.3.2",
  "generated_at": "2026-11-15T05:00:00Z",
  "generated_at_local": "2026-11-15 13:00:00 CST",
  "host": {
    "hostname": "ws-001",
    "os": "windows",
    "arch": "amd64",
    "ip_addresses": ["192.168.1.20"],
    "mac_addresses": ["aa:bb:cc:dd:ee:ff"]
  },
  "summary": {
    "program_count": 55,
    "ai_tool_count": 3
  },
  "ai_tools": ["claude-code", "opencode", "ollama"],
  "programs": [
    {
      "name": "Git",
      "version": "2.47.0",
      "publisher": "The Git Development Community",
      "install_location": "C:\\Program Files\\Git",
      "source": "registry",
      "is_ai_tool": false,
      "ai_tool_name": ""
    }
  ],
  "programs_by_source": {
    "registry": 34,
    "store": 3,
    "PATH": 3
  },
  "scan_duration_ms": 1300
}
```

`programs` 和 `ai_tools` 始终是数组，空结果不会输出 `null`。

`generated_at` 保持 RFC 3339（UTC），方便程序处理；`generated_at_local` 同时提供本地可读时间。XLSX 汇总表和 HTML 报告中的时间使用本地可读格式。

## 字段说明

### `host`

| 字段 | 说明 |
|------|------|
| `hostname` | 终端主机名 |
| `os` | `windows`、`darwin` 或 `linux` |
| `arch` | `amd64`、`arm64` 等 |
| `ip_addresses` | 非回环、非链路本地 IP 列表，IPv4 在前；已跳过 Docker/VPN 等虚拟网卡 |
| `mac_addresses` | 物理网卡的 MAC 地址列表；已跳过虚拟/容器网卡 |

### `programs[]`

| 字段 | 说明 |
|------|------|
| `name` | 软件显示名 |
| `version` | 版本（可能为空） |
| `publisher` | 发布者/厂商（可能为空） |
| `install_location` | 安装目录或可执行文件位置 |
| `source` | 来源，见下表 |
| `is_ai_tool` | 是否识别为 AI 工具 |
| `ai_tool_name` | AI 工具签名名（如 `opencode`） |

### 来源（`source`）

| 来源 | 含义 |
|------|------|
| `registry` | Windows 卸载注册表 |
| `store` | Microsoft Store / AppX |
| `apppaths` | Windows App Paths |
| `.lnk` | 开始菜单快捷方式（默认关闭；`-lnk` 开启） |
| `app_bundle` | macOS `.app` |
| `homebrew` / `homebrew-cask` | Homebrew formula / cask |
| `system_profiler` | macOS 应用清单 |
| `package_manager` | Linux/macOS 包管理器 |
| `.desktop` | Linux 桌面入口 |
| `opt` | Linux `/opt` |
| `PATH` | PATH 中的可执行文件 |
| `ai-signal` | 仅由配置目录/扩展/进程等系统信号识别的 AI 工具 |
| `wsl` | Windows 侧探测到的 WSL 内 AI 工具 |

## 跨机器汇总表

每次运行会在**与 HTML 报告相同的目录**更新一份 Excel 工作簿：

```text
<可执行文件所在目录>/sys-scanner/sys-scanner-summary.xlsx
```

也可以用 `-summary-out` 指定路径，或用 `-summary=false` 关闭。

特点：

- 真正的 `.xlsx` 文件，Excel/WPS 可直接打开，无需另存。
- 每个软件一行，带 `machine_id`、主机名、IP、MAC、系统、扫描时间、采集器版本。
- `scan_time` 使用本地可读格式，例如 `2026-11-15 18:00:00 CST`；它表示该机器记录**最后一次内容变化**的时间——内容没有变化的重复运行不会刷新这个时间，也不会重写文件。
- 同一台机器重复运行时，会按 `machine_id` 替换该机器的旧记录，并统计本次新增/删除数量。
- 软件版本变化不算新增/删除，只更新版本号（算作 updated）。
- 与上次内容完全一致时，不会重写文件（修改时间保持不变）。
- 不同机器（包括同一台机器的 Windows 与 WSL）会分别记录。
- 删除该文件即可重新开始汇总。
- 多台机器同时写同一个共享文件时可能互相覆盖；建议顺序执行，或每台机器写本地文件后统一合并。
- 如果已有同名文件损坏或表头不兼容，会自动改名为 `.bak` 后重新生成。

列说明：

| 列 | 说明 |
|----|------|
| `machine_id` | `主机名|系统|首个MAC`，用于替换同一台机器的旧记录 |
| `hostname` / `os` / `arch` | 主机信息 |
| `ip_addresses` / `mac_addresses` | 多个地址用 `; ` 分隔 |
| `scan_time` / `scanner_version` | 该机器记录最后一次内容变化的本地时间；内容未变化时不刷新 |
| `name` / `version` / `publisher` | 软件信息 |
| `location` / `source` | 安装位置、来源 |
| `is_ai_tool` / `ai_tool_name` | AI 工具标记 |

## 集中采集建议

默认清单会排除 Windows/Microsoft 自带组件和 Store 内置应用，只保留用户安装的软件。若合规审计需要完整视图，加 `-include-builtin` 重新生成；如需开始菜单快捷方式，加 `-lnk`。

sys-scanner 不会联网，采集方式由你决定：

- **Windows：** 通过组策略/Intune/SCCM 下发计划任务，定期执行：
  ```bat
  sys-scanner.exe -format json -out C:\ProgramData\Inventory\endpoint.json -no-open
  ```
- **macOS：** 通过 MDM 或 LaunchDaemon 定期执行，输出到受保护目录。
- **Linux：** 通过 cron/systemd timer 定期执行：
  ```bash
  sys-scanner -format json -out /var/lib/inventory/endpoint.json -no-open
  ```
- 采集代理读取生成的文件后上传到资产系统；也可以直接使用 `-out -` 从标准输出读取。

上传前建议先做最小化聚合：

```bash
sys-scanner -format json -out - -no-open | jq '{
  schema_version, generated_at, host, summary,
  ai_tools, programs_by_source
}'
```

## 版本兼容

- `schema_version` 在字段含义发生不兼容变化时递增。
- 新增可选字段不会改变主版本，采集端应忽略未知字段。
