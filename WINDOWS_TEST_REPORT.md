# sys-scanner Windows 测试报告

> 本文档记录 1.0.0 的测试情况。1.2.0 的新增能力与修复项见 [docs/AUDIT.md](./docs/AUDIT.md)。

测试日期：2026-08-13
测试环境：WSL2 (Linux) 交叉验证 + Windows 二进制静态验证

## 测试结果

| 测试项 | 结果 | 说明 |
|--------|------|------|
| Windows 交叉编译 | ✅ 通过 | `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...` 全部包编译成功 |
| Windows 二进制格式 | ✅ PE32+ | `sys-scanner-windows-amd64.exe` 为合法的 Windows x86-64 可执行文件（4.9MB） |
| Windows 纯逻辑单元测试 | ✅ 12/12 通过 | PATH 解析（分号/空格/去重）、发布者清洗等 Windows 特有逻辑 |
| Windows 代码静态检查 | ✅ go vet 干净 | 无 unsafe 指针警告 |
| 全平台测试套件 | ✅ 8/8 包通过 | classifier/report/scanner/merge/signatures/types 全部 PASS |
| AI 工具检测（Linux 实测） | ✅ opencode | 终端安装的 AI 工具通过签名数据库正确识别 |

## 未能执行的测试（环境限制）

本机为 WSL2 且 Windows interop 已关闭（无法从 WSL 启动 .exe），以下测试需要在**真实 Windows 系统**上运行：

- 注册表扫描（HKLM/HKCU Uninstall 键枚举）
- 开始菜单 .lnk 解析（COM IShellLink）
- Store 应用检测（Get-AppxPackage）
- 双击运行 + 浏览器打开报告

## 在 Windows 上测试步骤

1. 将 `dist/sys-scanner-windows-amd64.exe` 拷贝到 Windows 任意目录
2. 双击运行（或 PowerShell 中执行 `.\sys-scanner-windows-amd64.exe`）
3. 等待扫描完成（约 5-15 秒），控制台显示：
   ```
   Scanning installed programs...
   Found N programs across 5 sources (in Xs)
   Identified K AI tools: opencode, claude, ...
   Report saved to: C:\Users\<你>\AppData\Local\Temp\sys-scanner-report.html
   ```
4. 浏览器自动打开报告，可验证：
   - 全部程序列表（应包含 Chrome/VS Code/微信等真实应用）
   - "AI Tools Only" 标签页（应列出 opencode/claude/codex 等终端 AI 工具）
   - 排序/搜索/筛选功能
5. 测试完直接删除 .exe 即可，无残留
