use super::traits::{Tool, ToolResult};
use async_trait::async_trait;
use serde_json::json;

pub const MEMORY_CONDENSE_PAYLOAD_PREFIX: &str = "__MEMORY_CONDENSE_PAYLOAD__\n";

/// A tool that allows the agent to proactively summarize and condense its conversation history
/// to save context window tokens.
pub struct MemoryCondenseTool;

impl MemoryCondenseTool {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MemoryCondenseTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for MemoryCondenseTool {
    fn name(&self) -> &str {
        "self_memory_condense"
    }

    fn description(&self) -> &str {
        "Provide condensed memory to keep, and trigger a context reset using that memory.\n\nUse this tool when you have already summarized the important information from the current conversation, and you want to continue with only that summary as context. The system will clear the old history and keep ONLY your summary and the latest user request as the new background context.\n\nRules:\n- You MUST call self_memory_condense alone.\n- Do NOT call any other tools in the same response."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "The memory content that should be kept for future context. Provide a concise summary of the important facts, decisions, and ongoing plans. The content should be short, focused, and free of irrelevant details. Call self_memory_condense alone (no other tool calls in the same response)."
                }
            },
            "required": ["summary"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let summary = args
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();

        if summary.is_empty() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Summary cannot be empty".to_string()),
            });
        }

        // Return a special payload that the Agent loop will intercept and process.
        Ok(ToolResult {
            success: true,
            output: format!("{}{}", MEMORY_CONDENSE_PAYLOAD_PREFIX, summary),
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn execute_returns_special_payload() {
        let tool = MemoryCondenseTool::new();
        let result = tool
            .execute(json!({
                "summary": "We discussed the Rust memory model."
            }))
            .await
            .unwrap();

        assert!(result.success);
        assert!(result.output.starts_with(MEMORY_CONDENSE_PAYLOAD_PREFIX));
        assert!(result.output.contains("We discussed the Rust memory model."));
    }

    #[tokio::test]
    async fn execute_fails_on_empty_summary() {
        let tool = MemoryCondenseTool::new();
        let result = tool
            .execute(json!({
                "summary": "   "
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result.error.is_some());
    }
}
