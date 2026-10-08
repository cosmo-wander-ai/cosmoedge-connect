# CosmoEdge Connect

[English](README.md) | **简体中文**

让 AI 助手接入 CosmoEdge：查询告警、查看机位画面、启停已安装算法。

本地服务负责设备连接和执行。AI 客户端通过 MCP 或配套的 WorkBuddy 集成
请求操作并取得结果。

| 你想完成的工作 | CosmoEdge Connect 提供什么 |
| --- | --- |
| “昨天东门和西门分别有多少告警？” | 按时间、机位和算法查询留存记录，返回统计和原报告 |
| “看看这路画面有没有人，把图给我。” | 取得机位原图，交给宿主模型分析，并保留原图供后续追问 |
| “暂停这路算法，再按原设置恢复。” | 准备变更，在本机页面确认后执行，再核对设备状态 |

当前只连接一台 CosmoEdge 设备。画面理解由宿主模型完成；告警统计说明
实际读取范围。启停使用已有机位和已安装算法，沿用既有参数、区域和计划。

## 开始使用

1. 按[安装说明](docs/installation.zh-CN.md)安装本地服务，或从源码构建。
2. 在 CosmoEdge Connect 本机页面连接设备。
3. 配置 [MCP 客户端](docs/mcp.zh-CN.md)，或使用配套的 WorkBuddy Skill。
4. 按[快速上手](docs/getting-started.zh-CN.md)完成首次查询、看图和操作。

这是 CosmoEdge Connect 的 Alpha 源码预览版。各平台的检查项目及本次发布范围见
[兼容性（英文）](docs/compatibility.md)；安装包、客户端和设备验收必须对应实际使用的构建。
当前支持范围不包含微信、远程云端 MCP、多设备或定时巡检。

## 开发与集成

第三方客户端优先使用公开的 [MCP 工具接口](docs/mcp.zh-CN.md)。可选的
[官方运营 Skill](skills/cosmoedge-operations/SKILL.md)提供日期、机位、追问和
结果解释指导；不安装 Skill 也能调用工具。WorkBuddy 的配套 Python 客户端也使用
`cosmoedge-operations` Skill；按所选接入方式安装对应版本。官方适配器和服务
配套构建；内部 HTTP 接口用于适配器实现，不作为独立的长期兼容承诺。

```sh
make build
go run ./examples/mcp-client --server ./output/bin/cosmoedge-mcp --mock
```

以上命令构建两个公开程序，并通过合成服务运行[无需 Skill 的 MCP 示例](examples/mcp-client/main.go)，
验证工具调用、原件和请求恢复流程，无需设备或凭据。Windows 请使用
[开发指南（英文）](docs/development.md)中的直接构建命令，并为服务端路径加上 `.exe`。

构建依赖 Go 1.25+。WorkBuddy 包另需 Python 3.9+；测试环境的其他依赖见
[开发指南（英文）](docs/development.md)。适配器的构建命令和调用参数见
[MCP 接入](docs/mcp.zh-CN.md)。

| 文档 | 内容 |
| --- | --- |
| [架构（英文）](docs/architecture.md) | 服务、适配器、Skill 和运行状态的职责 |
| [业务约定（英文）](docs/operations.md) | 统计口径、图像来源、请求恢复和变更结果 |
| [测试（英文）](docs/testing.md) | 自动检查、真实客户端与设备验收 |
| [排障（英文）](docs/troubleshooting.md) | 连接、图片交付及请求恢复问题的诊断 |
| [升级与恢复（英文）](docs/upgrade.md) | 配套包更新、备份和状态恢复 |
| [贡献（英文）](CONTRIBUTING.md) | 开发和提交变更 |
| [安全（英文）](SECURITY.md) | 本地状态、凭据及漏洞报告 |

## 许可证

CosmoEdge Connect 采用 [Apache License 2.0](LICENSE)。第三方组件保留各自许可证，
见 [NOTICE](NOTICE)。
