# 本地 MCP 接入

[English](mcp.md) | **简体中文**

[首页](../README.zh-CN.md) · [安装](installation.zh-CN.md) · [快速开始](getting-started.zh-CN.md)

`cosmoedge-mcp` 通过 stdio 暴露 CosmoEdge Connect 运营服务。AI 客户端将这个适配器作为子进程启动；CosmoEdge Connect 服务必须已经安装并运行。适配器不会配置设备连接，也不会自行启动服务。

这是面向可信本机用户的接入方式。本版本不包含远程 Streamable HTTP、云端托管或多用户认证。各客户端的实际验收结果单独记录在[兼容性说明（英文）](compatibility.md)中。

## 安装与配置

构建包含 MCP 的配套安装包：

```sh
make package-macos VERSION=cosmoedge-connect-dev-local PACKAGE_DIR=../cosmoedge-connect-dev-local
```

底层 macOS 构建脚本支持 `--with-mcp`；Windows 打包目标也包含 MCP。先按[安装说明](installation.zh-CN.md)安装，再根据实际已安装的候选版本生成配置。安装包包含 WorkBuddy `cosmoedge-operations` Skill，但仅使用 MCP 时不需要 WorkBuddy，也不需要在宿主中导入 Skill。

完整的首次使用流程见[快速开始](getting-started.zh-CN.md)。

macOS：

```sh
/path/to/bundle/install.command mcp-config --client-id codex
```

Windows：

```powershell
& "$env:LOCALAPPDATA/CosmoEdgeConnect/cosmoedge-connect-control.ps1" -Action McpConfig -ClientId codex
```

选择 `codex` 或 `claude` 等客户端 ID，用于区分各自的私有操作日志。ID 以小写字母开头，最多 40 个字符，只能包含小写字母、数字或连字符。多个 stdio 进程可以共用一个已配置的日志根目录：持久化的请求只会被一个进程认领，其他竞争进程通过读取原操作来恢复，不会重复提交。需要分别管理时，不同客户端 ID 会生成各自的日志根目录。无论哪种方式，都不会自动建立可信的宿主对话身份；业务上下文仍须显式管理。

输出为 `mcpServers.cosmoedge` 配置项，包含 `command` 和 `args`。将这些值复制到客户端的本地 stdio MCP 配置中。有些客户端使用 JSON，有些使用设置页面或其他文件格式，但可执行文件和参数的值相同。不要把令牌内容粘贴到客户端配置中。升级或回滚后要重新生成配置，因为它指向实际已安装的候选版本。

命令的结构如下：

```sh
cosmoedge-mcp --base-url http://127.0.0.1:37789 --token-file /private/install/access.token --state-root /private/install/mcp-state/client-a --candidate-file /private/package/mcp-candidate.json
```

以上路径均为占位示例，实际路径应使用安装器的输出。MCP 私有操作日志与服务运行状态分开存放。`--candidate-file` 标识配套版本；服务、适配器和候选版本的身份必须一致。`--version-json` 可在不连接设备的情况下报告构建身份。Windows 上的候选 JSON 必须使用安装器设置的当前用户专用 DACL；手动保存一份未受保护的副本不是受支持的配置方式。

源码开发时可执行：

```sh
go build -buildvcs=false -o cosmoedge-mcp ./cmd/cosmoedge-mcp
```

任意单独构建的二进制不会继承已安装候选版本的身份。连接已安装服务时，应使用配套构建脚本。通用第三方 MCP 客户端不必使用相同的源码提交；只有官方适配器与服务需要配套。

### Codex CLI 启动排查

如果 Codex 在调用任何 CosmoEdge Connect 工具之前提示缺少 `codex-code-mode-host`，先检查 `codex` 启动入口是否为符号链接。macOS 上可用 `ls -l "$(command -v codex)"` 查看链接目标。直接调用与配套运行时位于一起的原始 Codex 可执行文件，或通过 Codex 安装器修复安装。可执行文件与配套运行时应来自同一次客户端安装，不要复制其他安装中的运行时。

这一客户端打包问题曾在 Codex CLI 0.155.0-alpha.16.3 上出现，通过直接调用现有可执行文件解决。它不表明 CosmoEdge Connect 服务有故障，也不需要关闭沙箱或审批控制。客户端排障结果不能作为新安装包的验收结论，参见[当前验收状态（英文）](compatibility.md)。

## 工具

通过 MCP `tools/list` 获取完整的 JSON 输入 schema。工具名和字段才是集成接口，不要解析本地化的用户摘要来对接。

| 工具 | 用途 |
| --- | --- |
| `cosmoedge_capabilities` | 报告适配器／服务能力、可用状态和新鲜的 `data.serverTime` |
| `cosmoedge_begin_context` | 为客户端本次工作创建显式业务上下文 |
| `cosmoedge_open_connection` | 打开本机设备接入页；省略上下文时自动创建 |
| `cosmoedge_catalog` | 读取当前来源、已安装算法、任务绑定和服务计算的 `data.totals` |
| `cosmoedge_summary` | 查询固定时间范围内的留存告警，返回统计和报告内容 |
| `cosmoedge_capture` | 获取一个来源的图像，供宿主模型分析 |
| `cosmoedge_get_operation` | 读取原操作并继续等待中的工作 |
| `cosmoedge_list_pending_operations` | 恢复该上下文中尚未完成的工作 |
| `cosmoedge_prepare_algorithm_change` | 为已有算法准备启用／停用提议 |
| `cosmoedge_open_review` | 打开该提议的本机业务确认页 |
| `cosmoedge_cancel` | 取消尚未执行的提议 |
| `cosmoedge_get_artifact` | 取回留存的同一份原图或原始报告 |

目录中的 `data.totals` 统计本次返回的列表，包含 `sourceCount`、`sourcesByKind`、`algorithmCount`、`taskCount`、`runningTaskCount`、`stoppedTaskCount` 和 `unknownRuntimeTaskCount`。优先使用这些值，无需逐项数长列表。来源分组为 `network_camera`、`test_video`、`usb_camera` 和 `unknown`；其他类型或缺失类型归入未知，原始目录项保持不变。运行数量只按明确的 `running`／`stopped` 状态计算，其他状态保留为未知。计数不会从启用开关推断运行状态，也不证明处理计数器已产生进度。

连接或更换设备时，直接用 `{}` 调用 `cosmoedge_open_connection`。适配器会在内部校验配套服务并创建上下文；保留返回的 `contextRef`，供本次工作流使用。也可以传入已有的 `contextRef`。显式传入无效或过期引用会被拒绝，不会自动替换。如果创建上下文后开页失败，仍保留返回的引用。其他业务工具仍要求提供上下文。

成功的开页回执包含 `ok: true`、`data.pageState: dispatched` 和 `data.interactionRequired: true`，表示已请求启动浏览器，不代表页面已渲染或设备已登录。专用接入页直接显示表单与已保存连接选项，无需读取设备目录。凭据与更换设备的确认留在本机页面。

其他业务请求的常规流程是 capabilities → context → catalog → 用户请求的业务操作。将 `contextRef` 与应用的对话或作业状态一起保存。它是适配器生成的作用域引用，不是经过验证的宿主对话身份。不要在无关对话之间共享引用。每次新的相对日期统计之前，先刷新 `cosmoedge_capabilities`，再根据当前服务时间计算查询范围；续查则沿用原来的范围。

`start` 和 `end` 是 RFC3339 绝对时刻，可以直接传 UTC `Z` 值。`timeZone` 控制自然日分组和显示，不会重新解释起止时刻。查询过去 24 小时时，以新鲜的 `serverTime` 作为 `end`，在 UTC 中减去 24 小时得到 `start`。严禁保持钟面时间不变、只把 `Z` 替换成 `+08:00`。改变表示法必须保持同一绝对时刻：`2026-05-06T12:00:00Z` 等于 `2026-05-06T20:00:00+08:00`，不等于 `2026-05-06T12:00:00+08:00`。按自然日期查询时，应先在业务时区计算所需的本地零点边界，再编码为时间参数。

## 请求恢复

抓图和算法变更提议除 `contextRef` 外还需要 `requestKey`。调用方为一个用户意图创建稳定的键，并在调用工具前保存。这个键与 MCP JSON-RPC 请求 ID 不同。适配器会先持久化映射后的服务请求，再发出提交。

传输断开后，使用原上下文和原请求键继续。恢复过程查询原操作，不会重新提交请求。同一个键对应的业务输入发生变化时会报冲突。尚未确认的提议、正在等待的操作和结果未知是不同状态。

已完成上下文的默认保留期为 30 天，在创建新上下文时检查保留期；未解决的操作会继续保留。维护通过本地 CLI 执行：在常规连接参数后加 `--maintenance` 可查看清理预演；用 `--retention-days` 选择保留期，用 `--apply` 执行符合条件的清理。没有一键清空所有待办的工具。已过期的产物不能重新生成后冒充原件。

服务会话另有 7 天的在线授权有效期。日志保留 30 天不会延长会话授权。会话过期后，离线 `cosmoedge_get_artifact` 仍可能取回留存原件，但在线读取操作仍需要原来的有效服务会话。不要为了绕过过期限制而创建新上下文、重新提交结果未知的设备变更。

普通重启时应保留私有操作日志。重新连接后，先调用 `cosmoedge_list_pending_operations`，再使用 `cosmoedge_get_operation`。不要仅因为响应看起来失败了，就新建上下文或请求键。客户端可以实现有时限的轮询并稍后继续，无需要求用户重复发出相同指令。

## 图像与报告

图像以 MCP 原生图像内容返回，报告以嵌入式文本资源返回。产物包含不透明引用和完整性元数据；`cosmoedge_get_artifact` 可在同一上下文中取回同一原件。接口不需要公开本地文件路径或提供任意抓取 URL。

宿主必须实际把图像传给模型，才能回答视觉问题。客户端还需要单独向用户展示附件。收到 MCP 原生图像／内容响应，本身不能证明每种客户端的 UI 都已经展示或保存了它。产物不可用或已过期，并不授权重新抓图或重新执行统计查询。

## 算法变更

`cosmoedge_prepare_algorithm_change` 为精确的来源／算法目标准备变更。`cosmoedge_open_review` 打开本机页面，不会确认变更。用户确认后，继续查询同一个操作，直到取得实际结果。MCP 工具权限不能代替业务确认。

用户撤回尚未执行的提议时，使用 `cosmoedge_cancel`。报告已取消之前，核对返回的取消标志和实际状态。若确认与取消并发发生，操作已经排队或运行，应先核清结果，再准备与其冲突的替代提议。操作一旦执行，反向变更就是一个新提议。分别保留原操作结果和当前回读，不要仅凭启用状态推断已经处理数据。

## 最小客户端示例

源码示例可以在不使用 Skill 的情况下验证接口：

```sh
go run ./examples/mcp-client --server /absolute/path/to/paired/cosmoedge-mcp --mock
```

`--mock` 启动一个合成数据的本机回环服务，演示工具、内容和恢复流程，包括多个 stdio 进程共用日志。它不会连接设备、调用模型，也不证明宿主 UI 已完成内容交付。服务端可执行文件必须是从本源码构建的适配器，或来自兼容的配套安装包。请在源码 checkout 中运行示例。

不带 `--mock` 时，示例只列出工具并调用 capabilities，不会抓图或修改设备。支持的参数和生命周期处理见[示例源码](../examples/mcp-client/main.go)。

## 第三方客户端接入检查

最小客户端可以在不使用官方 Skill 的情况下调用工具。可选的[运营 Skill](../skills/cosmoedge-operations/SKILL.md)提供流程指导，但不负责凭据、确认或设备执行。客户端需要：

1. 初始化 stdio MCP 并发现工具 schema。
2. 在有修改作用的调用之前，持久化上下文引用和请求键。
3. 明确处理工具错误、等待状态和不确定的提交结果。
4. 读取图像与资源内容，并向用户提供原件。
5. 打开本机接入／确认流程，并回读同一操作。
6. 分开保存独立对话的引用。

数据含义见[运营接口（英文）](operations.md)，验收场景见[测试说明（英文）](testing.md)。schema 或语义变化必须在发布说明中明确列出；未发布的开发构建不承诺跨版本 API 稳定性。
