# MemoryCondense 主动压缩工具与上下文重置机制

本文档主要说明本次引入的 `self_memory_condense` 工具（MemoryCondenseTool）及其配套的“主动压缩 + 上下文重置”机制在运行时行为上的变化、关键设计约束、以及代码改动位置，便于快速评审正确性与风险边界。

## 背景与目标

ZeroClaw 的 agent 运行在长对话/多轮工具调用场景下容易触达上下文窗口限制。本改动引入一个由模型自主触发的压缩工具 `self_memory_condense`，让模型在合适时机生成一段结构化 summary；运行时在检测到该工具成功执行后，将当前会话的历史上下文清空，并以 summary 作为新的背景继续执行，从而在不引入额外持久化语义的前提下延长“单次会话”的有效运行时长。

本机制的核心语义是：压缩发生后，新上下文不包含上一轮工具调用残留（避免 native tool calling 的消息序列约束被破坏），同时也避免将系统提醒/reminder 注入到 memory recall/autosave 的输入中，以免污染检索质量。

## 新增工具：`self_memory_condense`

工具实现位置： [memory\_condense.rs](file:///Users/bytedance/Projects/zeroclaw/wt/active_memory/src/tools/memory_condense.rs)

工具契约如下：

1. 工具名：`self_memory_condense`
2. 入参：JSON object，必填字段 `summary: string`
3. 返回：成功时在 `ToolResult.output` 中返回带前缀的特殊 payload：`__MEMORY_CONDENSE_PAYLOAD__\n{summary}`，供 agent loop 拦截处理
4. 关键约束：必须“单独调用”。即一次模型响应内不得与任何其他工具同时出现（包括并行/串行）。该约束在工具描述与参数描述中已经显式声明，并在 agent 侧进行了强制拦截（详见后文）。

## 上下文重置机制：Agent turn loop 的行为变化

核心改动位置： [agent.rs](file:///Users/bytedance/Projects/zeroclaw/wt/active_memory/src/agent/agent.rs)

### 1) “强制压缩”与“临近提醒”逻辑

新增字段 `turn_count_since_last_condense` 用于统计自上次压缩后的对话轮次。当启用配置后：

- 当轮次接近阈值（`condense_force_interval - 2`）时，将提醒文本拼接进本轮写入 history 的用户消息中，引导模型尽快调用 `self_memory_condense`。
- 当轮次达到阈值（`condense_force_interval`）时，会执行一次“强制清空历史”（不生成 summary），并在 history 注入系统提示，继续从最近的少量消息推进。

### 2) reminder 不再污染 memory recall / autosave

本次修复将“原始用户输入”和“写入 history 的用户输入”拆分为两份：

- `user_message_clean`：完全等同用户原始输入，用于 `memory_loader.load_context(...)` 和（如启用）`memory.store("user_msg", ...)` 的 autosave。
- `user_message_for_history`：用于写入 `self.history` 的消息文本，可能包含系统提醒/强制清空提示等辅助信息。

这样做的目的，是避免系统提醒被当作用户对话内容写入 Conversation memory，从而干扰 recall 的检索质量与后续 prompt 构造。

### 3) 禁止 self\_memory\_condense 与其他工具同轮调用（运行时强约束）

为了避免压缩发生时还同时存在其他工具调用结果导致上下文语义混乱（尤其是在 `parallel_tools` 模式下），agent 在解析出工具调用列表后会检查：

- 若本轮工具调用中包含 `self_memory_condense` 且总调用数不为 1，则不会执行任何工具；而是为每个调用构造 `success=false` 的错误结果，要求模型改为“只调用 self\_memory\_condense”。

### 4) 方案 A：压缩成功后立即重建 history，并跳过 tool results 注入

当且仅当本轮唯一工具调用是 `self_memory_condense`，且其返回 payload 能成功解析出 summary 时，agent 会：

1. 以 “system prompt（如果存在） + 一条 user 消息（包含 summary 与最新用户问题）” 重建 `self.history`
2. 将 `turn_count_since_last_condense` 置 0
3. 重置 loop detector（避免压缩前后的调用历史被视为同一段循环）
4. `continue` 进入下一次 tool-iteration，不再把上一轮的 tool results 写入 history

这样能保证在 native tool dispatcher 下不会出现非法的消息序列（例如 tool message 缺少对应的 assistant tool\_calls），同时也满足“压缩后新上下文不携带上一轮工具残留”的语义要求。

## 配置变更

配置项新增位置： [schema.rs](file:///Users/bytedance/Projects/zeroclaw/wt/active_memory/src/config/schema.rs#L1088-L1103)

新增字段位于 `[agent]` 配置中：

- `enable_memory_condense: bool`：是否启用主动压缩机制（默认 false）
- `condense_force_interval: usize`：触发强制清空/临近提醒的轮次阈值（默认 20；设为 0 表示禁用强制机制）

## 工具注册位置

工具模块与全量工具集合中已注册 `MemoryCondenseTool`：

- 模块声明与导出： [tools/mod.rs](file:///Users/bytedance/Projects/zeroclaw/wt/active_memory/src/tools/mod.rs#L60-L140)
- `all_tools_with_runtime` 注册： [tools/mod.rs](file:///Users/bytedance/Projects/zeroclaw/wt/active_memory/src/tools/mod.rs#L360-L390)

## 评审关注点（建议）

建议 reviewer 重点关注以下正确性与边界：

1. native tool dispatcher 的消息序列约束是否被遵守（压缩后不应留下孤立的 tool message）
2. `self_memory_condense` 与其他工具同轮调用时是否能稳定阻断，避免并行执行造成上下文不一致
3. reminder/强制提示是否仅影响 prompt/history，而不会污染 memory recall/autosave 的输入
