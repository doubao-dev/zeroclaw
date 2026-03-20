use crate::security::SecurityPolicy;
use crate::tools::feishu_bitable::{
    FeishuBitableAppTableFieldTool, FeishuBitableAppTableRecordTool, FeishuBitableAppTableTool,
    FeishuBitableAppTableViewTool, FeishuBitableAppTool,
};
use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use serde_json::{json, Map, Value};
use std::sync::Arc;

pub fn build_feishu_bitable_action_tools(
    app_id: String,
    app_secret: String,
    use_feishu: bool,
    security: Arc<SecurityPolicy>,
) -> Vec<Arc<dyn Tool>> {
    let app_tool: Arc<dyn Tool> = Arc::new(FeishuBitableAppTool::new(
        app_id.clone(),
        app_secret.clone(),
        use_feishu,
        security.clone(),
    ));
    let table_tool: Arc<dyn Tool> = Arc::new(FeishuBitableAppTableTool::new(
        app_id.clone(),
        app_secret.clone(),
        use_feishu,
        security.clone(),
    ));
    let field_tool: Arc<dyn Tool> = Arc::new(FeishuBitableAppTableFieldTool::new(
        app_id.clone(),
        app_secret.clone(),
        use_feishu,
        security.clone(),
    ));
    let view_tool: Arc<dyn Tool> = Arc::new(FeishuBitableAppTableViewTool::new(
        app_id.clone(),
        app_secret.clone(),
        use_feishu,
        security.clone(),
    ));
    let record_tool: Arc<dyn Tool> = Arc::new(FeishuBitableAppTableRecordTool::new(
        app_id,
        app_secret,
        use_feishu,
        security,
    ));

    let mut out: Vec<Arc<dyn Tool>> = Vec::new();
    out.extend(build_tools_from_one_of(
        app_tool,
        "feishu_bitable_app",
        &["create", "get", "list", "patch", "copy", "set_permission"],
    ));
    out.extend(build_tools_from_one_of(
        table_tool,
        "feishu_bitable_app_table",
        &[
            "create",
            "list",
            "patch",
            "delete",
            "batch_create",
            "batch_delete",
        ],
    ));
    out.extend(build_tools_from_one_of(
        field_tool,
        "feishu_bitable_app_table_field",
        &["create", "list", "update", "delete"],
    ));
    out.extend(build_tools_from_one_of(
        view_tool,
        "feishu_bitable_app_table_view",
        &["create", "get", "list", "patch", "delete"],
    ));
    out.extend(build_tools_from_one_of(
        record_tool,
        "feishu_bitable_app_table_record",
        &[
            "create",
            "list",
            "update",
            "delete",
            "batch_create",
            "batch_update",
            "batch_delete",
        ],
    ));
    out
}

fn build_tools_from_one_of(
    inner: Arc<dyn Tool>,
    base_name: &str,
    actions: &[&str],
) -> Vec<Arc<dyn Tool>> {
    let schema = inner.parameters_schema();
    let description = inner.description().to_string();
    actions
        .iter()
        .map(|action| {
            Arc::new(FixedActionTool {
                inner: inner.clone(),
                name: format!("{base_name}_{action}"),
                action: (*action).to_string(),
                description: format!("{description} Fixed action: {action}."),
                schema: extract_action_schema(&schema, action),
            }) as Arc<dyn Tool>
        })
        .collect()
}

fn extract_action_schema(schema: &Value, action: &str) -> Value {
    let Some(one_of) = schema.get("oneOf").and_then(Value::as_array) else {
        return json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        });
    };

    let branch = one_of.iter().find(|branch| {
        branch
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|props| props.get("action"))
            .and_then(|value| value.get("const"))
            .and_then(Value::as_str)
            == Some(action)
    });

    let Some(branch) = branch else {
        return json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        });
    };

    let mut properties = branch
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    properties.remove("action");

    let required = branch
        .get("required")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|name| *name != "action")
                .map(|name| Value::String(name.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let additional_properties = branch
        .get("additionalProperties")
        .cloned()
        .unwrap_or(Value::Bool(false));

    let mut out = Map::new();
    out.insert("type".to_string(), Value::String("object".to_string()));
    out.insert("properties".to_string(), Value::Object(properties));
    out.insert("required".to_string(), Value::Array(required));
    out.insert("additionalProperties".to_string(), additional_properties);
    Value::Object(out)
}

struct FixedActionTool {
    inner: Arc<dyn Tool>,
    name: String,
    action: String,
    description: String,
    schema: Value,
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
