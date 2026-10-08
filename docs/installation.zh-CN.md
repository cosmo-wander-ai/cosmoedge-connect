# 安装

[English](installation.md) | **简体中文**

[首页](../README.zh-CN.md) · [快速上手](getting-started.zh-CN.md) · [MCP 接入](mcp.zh-CN.md)

服务和官方客户端按同一源码候选配套构建。当前文档提供源码构建与开发包
安装方式；使用正式发布包时，应核对该版本的清单摘要和兼容性说明。

## 环境

| 用途 | 依赖 |
| --- | --- |
| 从源码构建服务或 MCP 适配器 | Go 1.25+ |
| 构建 WorkBuddy 包 | Go、Python 3.9+，macOS 包另需 `codesign` |
| 运行 WorkBuddy 配套包 | Python 3.9+ 和 WorkBuddy |
| 连接设备 | 本机可访问的 CosmoEdge 设备、已有机位与算法 |

开发检查还有 Node.js 等依赖，见[开发指南（英文）](development.md)。编译成功不代表
该平台的桌面客户端和真实设备验收已完成。

## macOS 本地服务

在干净源码目录构建，输出到工作树之外：

```sh
python3 scripts/build-connect-macos.py --development-app --with-mcp --version cosmoedge-connect-dev-local --output /absolute/path/to/cosmoedge-connect-dev-local
```

记录构建输出的 `manifestSHA256`，将下方 `<manifest-sha256>` 替换为该值，
再通过同一包安装：

```sh
/absolute/path/to/cosmoedge-connect-dev-local/install.command install --bundle /absolute/path/to/cosmoedge-connect-dev-local --expected-manifest-sha256 <manifest-sha256>
```

如果使用 MCP，安装后直接生成客户端配置，无需安装 WorkBuddy 或导入其 Skill：

```sh
/absolute/path/to/cosmoedge-connect-dev-local/install.command mcp-config --client-id codex
```

如果使用 WorkBuddy，再导入包内 `cosmoedge-operations.zip`，随后运行：

```sh
/absolute/path/to/cosmoedge-connect-dev-local/install.command finalize-skill-import
/absolute/path/to/cosmoedge-connect-dev-local/install.command status
```

WorkBuddy 集成升级后开启新对话并重新选择 Skill。MCP 升级后重新生成客户端配置。
从所选客户端打开本机连接页，连接设备并查询目录。
详细的安装、启动和恢复见[macOS 配套包说明（英文）](../integrations/workbuddy/deploy/macos/PAIRED-INSTALL.md)。
`--development-app` 是开发签名，不等于已完成公开分发签名或公证。

## Windows 本地服务

构建与生命周期入口见[Windows 安装说明（英文）](../integrations/workbuddy/deploy/windows/README.md)。
Windows 安装和附件交付必须在 Windows 实际运行；macOS 的结果不覆盖它。
使用当前登录用户的普通 PowerShell 窗口安装，保持用户级文件归属；安装位置是
`%LOCALAPPDATA%/CosmoEdgeConnect`，不需要管理员权限。
首次安装令牌初始化以该说明中的当前实现状态为准。

## MCP 客户端

本地 MCP 适配器连接已配置的 CosmoEdge Connect 服务。构建命令、配置字段和工具用法见
[MCP 接入](mcp.zh-CN.md)。每个客户端单独验证图片读取、报告交付和确认页流程。

## Linux

当前保留 Go 服务的源码构建路径，尚无经过验收的 Linux 桌面安装包。
平台边界见
[Linux 说明（英文）](../integrations/workbuddy/deploy/linux/README.md)。

## 升级和恢复

保留上一配套包和安装器生成的恢复点，先核对当前操作，再升级文件。
恢复安装文件不等于回滚设备任务或数据库。跨版本状态兼容和原设备配置
必须分别验证，见[升级与恢复（英文）](upgrade.md)。
