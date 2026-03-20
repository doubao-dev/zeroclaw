use crate::config::Config;
use crate::security::SecurityPolicy;
use crate::tools::channel_ack_config::ChannelAckConfigTool;
use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;

pub fn build_channel_ack_action_tools(
    config: Arc<Config>,
    security: Arc<SecurityPolicy>,
) -> Vec<Arc<dyn Tool>> {
    let inner: Arc<dyn Tool> = Arc::new(ChannelAckConfigTool::new(config, security));
    vec![
        Arc::new(FixedActionTool::new(
            inner.clone(),
            "channel_ack_config_get",
            "get",
            json!({
                "type": "object",
                "properties": {
                    "channel": {
                        "type": "string",
                        "enum": ["telegram", "discord", "lark", "feishu"]
                    }
                },
                "required": ["channel"],
                "additionalProperties": false
            }),
        )),
        Arc::new(FixedActionTool::new(
            inner.clone(),
            "channel_ack_config_set",
            "set",
            json!({
                "type": "object",
                "properties": {
                    "channel": {
                        "type": "string",
                        "enum": ["telegram", "discord", "lark", "feishu"]
                    },
                    "enabled": {"type": "boolean"},
                    "strategy": {
                        "type": "string",
                        "enum": ["random", "first"],
                        "description": "Reaction strategy. Omit this field to keep current value."
                    },
                    "sample_rate": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    "emojis": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Emoji pool. Runtime also accepts comma-separated string for compatibility."
                    },
                    "rules": {}
                },
                "required": ["channel"],
                "additionalProperties": false
            }),
        )),
        Arc::new(FixedActionTool::new(
            inner.clone(),
            "channel_ack_config_add_rule",
            "add_rule",
            json!({
                "type": "object",
                "properties": {
                    "channel": {
                        "type": "string",
                        "enum": ["telegram", "discord", "lark", "feishu"]
                    },
                    "rule": {"type": "object"}
                },
                "required": ["channel", "rule"],
                "additionalProperties": false
            }),
        )),
        Arc::new(FixedActionTool::new(
            inner.clone(),
            "channel_ack_config_remove_rule",
            "remove_rule",
            json!({
                "type": "object",
                "properties": {
                    "channel": {
                        "type": "string",
                        "enum": ["telegram", "discord", "lark", "feishu"]
                    },
                    "index": {"type": "integer", "minimum": 0}
                },
                "required": ["channel", "index"],
                "additionalProperties": false
            }),
        )),
        Arc::new(FixedActionTool::new(
            inner.clone(),
            "channel_ack_config_clear_rules",
            "clear_rules",
            json!({
                "type": "object",
                "properties": {
                    "channel": {
                        "type": "string",
                        "enum": ["telegram", "discord", "lark", "feishu"]
                    }
                },
                "required": ["channel"],
                "additionalProperties": false
            }),
        )),
        Arc::new(FixedActionTool::new(
            inner.clone(),
            "channel_ack_config_unset",
            "unset",
            json!({
                "type": "object",
                "properties": {
                    "channel": {
                        "type": "string",
                        "enum": ["telegram", "discord", "lark", "feishu"]
                    }
                },
                "required": ["channel"],
                "additionalProperties": false
            }),
        )),
        Arc::new(FixedActionTool::new(
            inner,
            "channel_ack_config_simulate",
            "simulate",
            json!({
                "type": "object",
                "properties": {
                    "channel": {
                        "type": "string",
                        "enum": ["telegram", "discord", "lark", "feishu"]
                    },
                    "text": {"type": "string"},
                    "sender_id": {},
                    "chat_id": {},
                    "chat_type": {"type": "string", "enum": ["direct", "group"]},
                    "locale_hint": {},
                    "runs": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "defaults": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Default emoji pool. Runtime also accepts comma-separated string for compatibility."
                    }
                },
                "required": ["channel", "text"],
                "additionalProperties": false
            }),
        )),
    ]
}

struct FixedActionTool {
    inner: Arc<dyn Tool>,
    name: String,
    action: String,
    description: String,
    schema: Value,
}

impl FixedActionTool {
    fn new(inner: Arc<dyn Tool>, name: &str, action: &str, schema: Value) -> Self {
        Self {
            inner,
            name: name.to_string(),
            action: action.to_string(),
            description: format!("{} Fixed action: {action}.", name),
            schema,
        }
    }
}

#[async_trait]
impl Tool for FixedActionTool {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn parameters_schema(&self) -> Value {
        self.schema.clone()
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let mut payload = match args {
            Value::Object(map) => map,
            _ => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Arguments must be a JSON object".to_string()),
                });
            }
        };
        payload.insert("action".to_string(), Value::String(self.action.clone()));
        self.inner.execute(Value::Object(payload)).await
    }
}
