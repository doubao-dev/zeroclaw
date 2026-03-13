use crate::security::{policy::ToolOperation, SecurityPolicy};
use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use reqwest::Method;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const FEISHU_BASE_URL: &str = "https://open.feishu.cn/open-apis";
const LARK_BASE_URL: &str = "https://open.larksuite.com/open-apis";
const TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(120);
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(7200);
const INVALID_ACCESS_TOKEN_CODE: i64 = 99_991_663;

const APP_ACTIONS: &[&str] = &["create", "get", "list", "patch", "copy"];
const TABLE_ACTIONS: &[&str] = &["create", "list", "patch", "delete", "batch_create", "batch_delete"];
const RECORD_ACTIONS: &[&str] = &[
    "create",
    "list",
    "update",
    "delete",
    "batch_create",
    "batch_update",
    "batch_delete",
];

#[derive(Debug, Clone)]
struct CachedTenantToken {
    value: String,
    refresh_after: Instant,
}

#[derive(Clone)]
struct FeishuTenantClient {
    app_id: String,
    app_secret: String,
    use_feishu: bool,
    tenant_token: Arc<RwLock<Option<CachedTenantToken>>>,
    client: reqwest::Client,
}

impl FeishuTenantClient {
    fn new(app_id: String, app_secret: String, use_feishu: bool) -> Self {
        Self {
            app_id,
            app_secret,
            use_feishu,
            tenant_token: Arc::new(RwLock::new(None)),
            client: crate::config::build_runtime_proxy_client("tool.feishu_bitable"),
        }
    }

    fn api_base(&self) -> &str {
        if self.use_feishu {
            FEISHU_BASE_URL
        } else {
            LARK_BASE_URL
        }
    }

    async fn get_tenant_access_token(&self) -> anyhow::Result<String> {
        {
            let cached = self.tenant_token.read().await;
            if let Some(token) = cached.as_ref() {
                if Instant::now() < token.refresh_after {
                    return Ok(token.value.clone());
                }
            }
        }

        let url = format!(
            "{}/auth/v3/tenant_access_token/internal",
            self.api_base()
        );
        let body = json!({
            "app_id": self.app_id,
            "app_secret": self.app_secret,
        });

        let resp = self.client.post(&url).json(&body).send().await?;
        let status = resp.status();
        let payload = parse_json_or_empty(resp).await?;

        if !status.is_success() {
            anyhow::bail!(
                "tenant_access_token request failed: status={}, body={}",
                status,
                sanitize_api_json(&payload)
            );
        }

        ensure_api_success(&payload, "tenant_access_token")?;
        let token = payload
            .get("tenant_access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("tenant_access_token missing from response"))?
            .to_string();

        let ttl_seconds = extract_ttl_seconds(&payload);
        let refresh_after = next_refresh_deadline(Instant::now(), ttl_seconds);

        let mut cached = self.tenant_token.write().await;
        *cached = Some(CachedTenantToken {
            value: token.clone(),
            refresh_after,
        });

        Ok(token)
    }

    async fn authed_request(
        &self,
        method: Method,
        url: &str,
        body: Option<Value>,
    ) -> anyhow::Result<Value> {
        let token = self.get_tenant_access_token().await?;
        let mut builder = self
            .client
            .request(method.clone(), url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json; charset=utf-8");

        if let Some(ref b) = body {
            builder = builder.json(b);
        }

        let resp = builder.send().await?;
        let status = resp.status();
        let payload = parse_json_or_empty(resp).await?;

        if status.is_success() {
            if api_error_code(&payload) == Some(INVALID_ACCESS_TOKEN_CODE) {
                {
                    let mut cached = self.tenant_token.write().await;
                    *cached = None;
                }
                let token = self.get_tenant_access_token().await?;
                let mut builder = self
                    .client
                    .request(method, url)
                    .header("Authorization", format!("Bearer {}", token))
                    .header("Content-Type", "application/json; charset=utf-8");
                if let Some(ref b) = body {
                    builder = builder.json(b);
                }
                let resp = builder.send().await?;
                let status = resp.status();
                let payload = parse_json_or_empty(resp).await?;
                if !status.is_success() {
                    anyhow::bail!(
                        "request failed: status={}, body={}",
                        status,
                        sanitize_api_json(&payload)
                    );
                }
                ensure_api_success(&payload, "oapi")?;
                return Ok(payload);
            }

            ensure_api_success(&payload, "oapi")?;
            return Ok(payload);
        }

        anyhow::bail!(
            "request failed: status={}, body={}",
            status,
            sanitize_api_json(&payload)
        );
    }
}

pub struct FeishuBitableAppTool {
    client: FeishuTenantClient,
    security: Arc<SecurityPolicy>,
}

impl FeishuBitableAppTool {
    pub fn new(app_id: String, app_secret: String, use_feishu: bool, security: Arc<SecurityPolicy>) -> Self {
        Self {
            client: FeishuTenantClient::new(app_id, app_secret, use_feishu),
            security,
        }
    }

    async fn execute_action(&self, action: &str, args: &Value) -> anyhow::Result<Value> {
        match action {
            "create" => {
                let name = args
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'name' parameter"))?
                    .to_string();
                let folder_token = args.get("folder_token").and_then(Value::as_str);

                let mut body = json!({ "name": name });
                if let Some(token) = folder_token {
                    body["folder_token"] = Value::String(token.to_string());
                }

                let url = format!("{}/bitable/v1/apps", self.client.api_base());
                let payload = self
                    .client
                    .authed_request(Method::POST, &url, Some(body))
                    .await?;
                Ok(payload)
            }
            "get" => {
                let app_token = args
                    .get("app_token")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'app_token' parameter"))?;
                let url = format!("{}/bitable/v1/apps/{}", self.client.api_base(), app_token);
                let payload = self
                    .client
                    .authed_request(Method::GET, &url, None)
                    .await?;
                Ok(payload)
            }
            "patch" => {
                let app_token = args
                    .get("app_token")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'app_token' parameter"))?;
                let mut app = json!({});
                if let Some(name) = args.get("name").and_then(Value::as_str) {
                    app["name"] = Value::String(name.to_string());
                }
                if let Some(is_advanced) = args.get("is_advanced").and_then(Value::as_bool) {
                    app["is_advanced"] = Value::Bool(is_advanced);
                }
                if app.as_object().map(|o| o.is_empty()).unwrap_or(true) {
                    anyhow::bail!("No fields provided for patch; supply 'name' and/or 'is_advanced'");
                }
                let url = format!("{}/bitable/v1/apps/{}", self.client.api_base(), app_token);
                let payload = self
                    .client
                    .authed_request(Method::PATCH, &url, Some(json!({ "app": app })))
                    .await?;
                Ok(payload)
            }
            "copy" => {
                let app_token = args
                    .get("app_token")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'app_token' parameter"))?;
                let name = args
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'name' parameter"))?
                    .to_string();
                let folder_token = args.get("folder_token").and_then(Value::as_str);
                let mut body = json!({ "name": name });
                if let Some(token) = folder_token {
                    body["folder_token"] = Value::String(token.to_string());
                }
                let url = format!(
                    "{}/bitable/v1/apps/{}/copy",
                    self.client.api_base(),
                    app_token
                );
                let payload = self
                    .client
                    .authed_request(Method::POST, &url, Some(body))
                    .await?;
                Ok(payload)
            }
            "list" => {
                let folder_token = args.get("folder_token").and_then(Value::as_str);
                let page_size = args.get("page_size").and_then(Value::as_u64);
                let page_token = args.get("page_token").and_then(Value::as_str);

                let mut url = format!("{}/drive/v1/files?type=bitable", self.client.api_base());
                if let Some(token) = folder_token {
                    url.push_str(&format!("&folder_token={}", urlencoding::encode(token)));
                }
                if let Some(size) = page_size {
                    url.push_str(&format!("&page_size={}", size));
                }
                if let Some(token) = page_token {
                    url.push_str(&format!("&page_token={}", urlencoding::encode(token)));
                }

                let payload = self
                    .client
                    .authed_request(Method::GET, &url, None)
                    .await?;
                Ok(payload)
            }
            _ => anyhow::bail!("Unsupported action: {}", action),
        }
    }
}

#[async_trait]
impl Tool for FeishuBitableAppTool {
    fn name(&self) -> &str {
        "feishu_bitable_app"
    }

    fn description(&self) -> &str {
        "Feishu/Lark Bitable app management using tenant_access_token. Actions: create, get, list, patch, copy."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "enum": APP_ACTIONS },
                "app_token": { "type": "string" },
                "name": { "type": "string" },
                "folder_token": { "type": "string" },
                "is_advanced": { "type": "boolean" },
                "page_size": { "type": "integer" },
                "page_token": { "type": "string" }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let action = match args.get("action").and_then(Value::as_str) {
            Some(v) if !v.trim().is_empty() => v,
            _ => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing 'action' parameter".to_string()),
                });
            }
        };

        let operation = match action {
            "get" | "list" => ToolOperation::Read,
            _ => ToolOperation::Act,
        };
        if let Err(e) = self
            .security
            .enforce_tool_operation(operation, "feishu_bitable_app")
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e),
            });
        }

        match self.execute_action(action, &args).await {
            Ok(result) => Ok(ToolResult {
                success: true,
                output: result.to_string(),
                error: None,
            }),
            Err(err) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(crate::providers::sanitize_api_error(&err.to_string())),
            }),
        }
    }
}

pub struct FeishuBitableAppTableTool {
    client: FeishuTenantClient,
    security: Arc<SecurityPolicy>,
}

impl FeishuBitableAppTableTool {
    pub fn new(app_id: String, app_secret: String, use_feishu: bool, security: Arc<SecurityPolicy>) -> Self {
        Self {
            client: FeishuTenantClient::new(app_id, app_secret, use_feishu),
            security,
        }
    }

    async fn execute_action(&self, action: &str, args: &Value) -> anyhow::Result<Value> {
        let app_token = args
            .get("app_token")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Missing 'app_token' parameter"))?;

        match action {
            "create" => {
                let table_value = args
                    .get("table")
                    .ok_or_else(|| anyhow::anyhow!("Missing 'table' parameter"))?;
                let table_obj = table_value
                    .as_object()
                    .ok_or_else(|| anyhow::anyhow!("'table' must be an object"))?;

                let mut table_obj = table_obj.clone();
                if table_obj
                    .get("name")
                    .and_then(Value::as_str)
                    .map(|s| !s.trim().is_empty())
                    != Some(true)
                {
                    let fallback_name = args
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .ok_or_else(|| anyhow::anyhow!("Missing table name; provide 'table.name' or top-level 'name'"))?;
                    table_obj.insert("name".to_string(), Value::String(fallback_name.to_string()));
                }

                if let Some(fields_val) = table_obj.get("fields").cloned() {
                    if let Some(fields) = fields_val.as_array() {
                        let mut out = Vec::with_capacity(fields.len());
                        for field in fields {
                            let Some(field_obj) = field.as_object() else {
                                anyhow::bail!("table.fields entries must be objects");
                            };
                            let mut field_obj = field_obj.clone();
                            let ty = field_obj.get("type").and_then(Value::as_i64);
                            if matches!(ty, Some(7) | Some(15)) {
                                field_obj.remove("property");
                            }
                            out.push(Value::Object(field_obj));
                        }
                        table_obj.insert("fields".to_string(), Value::Array(out));
                    } else {
                        anyhow::bail!("'table.fields' must be an array");
                    }
                }

                let table = Value::Object(table_obj);
                let url = format!("{}/bitable/v1/apps/{}/tables", self.client.api_base(), app_token);
                let payload = self
                    .client
                    .authed_request(Method::POST, &url, Some(json!({ "table": table })))
                    .await?;
                Ok(payload)
            }
            "list" => {
                let page_size = args.get("page_size").and_then(Value::as_u64);
                let page_token = args.get("page_token").and_then(Value::as_str);
                let mut url = format!(
                    "{}/bitable/v1/apps/{}/tables",
                    self.client.api_base(),
                    app_token
                );
                let mut sep = '?';
                if let Some(size) = page_size {
                    url.push(sep);
                    sep = '&';
                    url.push_str(&format!("page_size={}", size));
                }
                if let Some(token) = page_token {
                    url.push(sep);
                    url.push_str(&format!("page_token={}", urlencoding::encode(token)));
                }
                let payload = self
                    .client
                    .authed_request(Method::GET, &url, None)
                    .await?;
                Ok(payload)
            }
            "patch" => {
                let table_id = args
                    .get("table_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'table_id' parameter"))?;
                let name = args
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'name' parameter"))?
                    .to_string();
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}",
                    self.client.api_base(),
                    app_token,
                    table_id
                );
                let payload = self
                    .client
                    .authed_request(Method::PATCH, &url, Some(json!({ "table": { "name": name } })))
                    .await?;
                Ok(payload)
            }
            "delete" => {
                let table_id = args
                    .get("table_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'table_id' parameter"))?;
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}",
                    self.client.api_base(),
                    app_token,
                    table_id
                );
                let payload = self
                    .client
                    .authed_request(Method::DELETE, &url, None)
                    .await?;
                Ok(payload)
            }
            "batch_create" => {
                let tables = args
                    .get("tables")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'tables' parameter"))?
                    .clone();
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/batch_create",
                    self.client.api_base(),
                    app_token
                );
                let payload = self
                    .client
                    .authed_request(Method::POST, &url, Some(json!({ "tables": tables })))
                    .await?;
                Ok(payload)
            }
            "batch_delete" => {
                let table_ids = args
                    .get("table_ids")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'table_ids' parameter"))?
                    .clone();
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/batch_delete",
                    self.client.api_base(),
                    app_token
                );
                let payload = self
                    .client
                    .authed_request(Method::POST, &url, Some(json!({ "table_ids": table_ids })))
                    .await?;
                Ok(payload)
            }
            _ => anyhow::bail!("Unsupported action: {}", action),
        }
    }
}

#[async_trait]
impl Tool for FeishuBitableAppTableTool {
    fn name(&self) -> &str {
        "feishu_bitable_app_table"
    }

    fn description(&self) -> &str {
        "Feishu/Lark Bitable table management using tenant_access_token. Actions: create, list, patch, delete, batch_create, batch_delete."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "enum": TABLE_ACTIONS },
                "app_token": { "type": "string" },
                "table_id": { "type": "string" },
                "name": { "type": "string" },
                "table": { "type": "object" },
                "tables": { "type": "array", "items": { "type": "object" } },
                "table_ids": { "type": "array", "items": { "type": "string" } },
                "page_size": { "type": "integer" },
                "page_token": { "type": "string" }
            },
            "required": ["action", "app_token"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let action = match args.get("action").and_then(Value::as_str) {
            Some(v) if !v.trim().is_empty() => v,
            _ => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing 'action' parameter".to_string()),
                });
            }
        };

        let operation = match action {
            "list" => ToolOperation::Read,
            _ => ToolOperation::Act,
        };
        if let Err(e) = self
            .security
            .enforce_tool_operation(operation, "feishu_bitable_app_table")
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e),
            });
        }

        match self.execute_action(action, &args).await {
            Ok(result) => Ok(ToolResult {
                success: true,
                output: result.to_string(),
                error: None,
            }),
            Err(err) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(crate::providers::sanitize_api_error(&err.to_string())),
            }),
        }
    }
}

pub struct FeishuBitableAppTableRecordTool {
    client: FeishuTenantClient,
    security: Arc<SecurityPolicy>,
}

impl FeishuBitableAppTableRecordTool {
    pub fn new(app_id: String, app_secret: String, use_feishu: bool, security: Arc<SecurityPolicy>) -> Self {
        Self {
            client: FeishuTenantClient::new(app_id, app_secret, use_feishu),
            security,
        }
    }

    async fn field_name_to_id_map(
        &self,
        app_token: &str,
        table_id: &str,
    ) -> anyhow::Result<HashMap<String, String>> {
        let mut page_token: Option<String> = None;
        let mut map: HashMap<String, String> = HashMap::new();
        loop {
            let mut url = format!(
                "{}/bitable/v1/apps/{}/tables/{}/fields?page_size=100",
                self.client.api_base(),
                app_token,
                table_id
            );
            if let Some(token) = page_token.as_deref() {
                url.push_str(&format!("&page_token={}", urlencoding::encode(token)));
            }

            let payload = self.client.authed_request(Method::GET, &url, None).await?;
            let data = payload
                .get("data")
                .ok_or_else(|| anyhow::anyhow!("fields list response missing 'data'"))?;
            let items = data
                .get("items")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow::anyhow!("fields list response missing 'data.items'"))?;

            for item in items {
                let field_id = item.get("field_id").and_then(Value::as_str);
                let field_name = item.get("field_name").and_then(Value::as_str);
                if let (Some(id), Some(name)) = (field_id, field_name) {
                    map.entry(name.to_string()).or_insert_with(|| id.to_string());
                }
            }

            let has_more = data.get("has_more").and_then(Value::as_bool).unwrap_or(false);
            if !has_more {
                break;
            }
            page_token = data
                .get("page_token")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            if page_token.as_deref().map(|s| s.is_empty()).unwrap_or(true) {
                break;
            }
        }
        Ok(map)
    }

    fn should_translate_field_keys(fields: &serde_json::Map<String, Value>) -> bool {
        fields.keys().any(|k| !k.starts_with("fld"))
    }

    fn translate_fields(
        fields: &serde_json::Map<String, Value>,
        map: &HashMap<String, String>,
    ) -> Value {
        let mut out = serde_json::Map::with_capacity(fields.len());
        for (k, v) in fields {
            if let Some(field_id) = map.get(k) {
                out.insert(field_id.clone(), v.clone());
            } else {
                out.insert(k.clone(), v.clone());
            }
        }
        Value::Object(out)
    }

    fn translate_records(
        records: &[Value],
        map: &HashMap<String, String>,
    ) -> anyhow::Result<Value> {
        let mut out: Vec<Value> = Vec::with_capacity(records.len());
        for record in records {
            let obj = record
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("each item in 'records' must be an object"))?;
            let mut cloned = obj.clone();
            if let Some(fields_val) = obj.get("fields") {
                let fields_obj = fields_val
                    .as_object()
                    .ok_or_else(|| anyhow::anyhow!("record.fields must be an object"))?;
                let translated = Self::translate_fields(fields_obj, map);
                cloned.insert("fields".to_string(), translated);
            }
            out.push(Value::Object(cloned));
        }
        Ok(Value::Array(out))
    }

    async fn execute_action(&self, action: &str, args: &Value) -> anyhow::Result<Value> {
        let app_token = args
            .get("app_token")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Missing 'app_token' parameter"))?;
        let table_id = args
            .get("table_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Missing 'table_id' parameter"))?;

        match action {
            "create" => {
                let fields = args
                    .get("fields")
                    .and_then(Value::as_object)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'fields' parameter"))?;
                if fields.is_empty() {
                    anyhow::bail!("'fields' cannot be empty");
                }
                let fields = if Self::should_translate_field_keys(fields) {
                    let map = self.field_name_to_id_map(app_token, table_id).await?;
                    Self::translate_fields(fields, &map)
                } else {
                    Value::Object(fields.clone())
                };
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/records?user_id_type=open_id",
                    self.client.api_base(),
                    app_token,
                    table_id
                );
                let payload = self
                    .client
                    .authed_request(Method::POST, &url, Some(json!({ "fields": fields })))
                    .await?;
                Ok(payload)
            }
            "update" => {
                let record_id = args
                    .get("record_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'record_id' parameter"))?;
                let fields = args
                    .get("fields")
                    .and_then(Value::as_object)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'fields' parameter"))?;
                if fields.is_empty() {
                    anyhow::bail!("'fields' cannot be empty");
                }
                let fields = if Self::should_translate_field_keys(fields) {
                    let map = self.field_name_to_id_map(app_token, table_id).await?;
                    Self::translate_fields(fields, &map)
                } else {
                    Value::Object(fields.clone())
                };
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/records/{}?user_id_type=open_id",
                    self.client.api_base(),
                    app_token,
                    table_id,
                    record_id
                );
                let payload = self
                    .client
                    .authed_request(Method::PUT, &url, Some(json!({ "fields": fields })))
                    .await?;
                Ok(payload)
            }
            "delete" => {
                let record_id = args
                    .get("record_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'record_id' parameter"))?;
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/records/{}",
                    self.client.api_base(),
                    app_token,
                    table_id,
                    record_id
                );
                let payload = self
                    .client
                    .authed_request(Method::DELETE, &url, None)
                    .await?;
                Ok(payload)
            }
            "batch_create" => {
                let records = args
                    .get("records")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'records' parameter"))?;
                if records.is_empty() {
                    anyhow::bail!("'records' cannot be empty");
                }
                let records = {
                    let needs_translate = records.iter().any(|r| {
                        r.get("fields")
                            .and_then(Value::as_object)
                            .map(Self::should_translate_field_keys)
                            .unwrap_or(false)
                    });
                    if needs_translate {
                        let map = self.field_name_to_id_map(app_token, table_id).await?;
                        Self::translate_records(records, &map)?
                    } else {
                        Value::Array(records.clone())
                    }
                };
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/records/batch_create?user_id_type=open_id",
                    self.client.api_base(),
                    app_token,
                    table_id
                );
                let payload = self
                    .client
                    .authed_request(Method::POST, &url, Some(json!({ "records": records })))
                    .await?;
                Ok(payload)
            }
            "batch_update" => {
                let records = args
                    .get("records")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'records' parameter"))?;
                if records.is_empty() {
                    anyhow::bail!("'records' cannot be empty");
                }
                let records = {
                    let needs_translate = records.iter().any(|r| {
                        r.get("fields")
                            .and_then(Value::as_object)
                            .map(Self::should_translate_field_keys)
                            .unwrap_or(false)
                    });
                    if needs_translate {
                        let map = self.field_name_to_id_map(app_token, table_id).await?;
                        Self::translate_records(records, &map)?
                    } else {
                        Value::Array(records.clone())
                    }
                };
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/records/batch_update?user_id_type=open_id",
                    self.client.api_base(),
                    app_token,
                    table_id
                );
                let payload = self
                    .client
                    .authed_request(Method::POST, &url, Some(json!({ "records": records })))
                    .await?;
                Ok(payload)
            }
            "batch_delete" => {
                let record_ids = args
                    .get("record_ids")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'record_ids' parameter"))?;
                if record_ids.is_empty() {
                    anyhow::bail!("'record_ids' cannot be empty");
                }
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/records/batch_delete",
                    self.client.api_base(),
                    app_token,
                    table_id
                );
                let payload = self
                    .client
                    .authed_request(Method::POST, &url, Some(json!({ "record_ids": record_ids })))
                    .await?;
                Ok(payload)
            }
            "list" => {
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/records/search?user_id_type=open_id",
                    self.client.api_base(),
                    app_token,
                    table_id
                );

                let mut body = json!({});
                if let Some(view_id) = args.get("view_id").and_then(Value::as_str) {
                    body["view_id"] = Value::String(view_id.to_string());
                }
                if let Some(field_names) = args.get("field_names").and_then(Value::as_array) {
                    body["field_names"] = Value::Array(field_names.clone());
                }
                if let Some(filter) = args.get("filter") {
                    body["filter"] = filter.clone();
                }
                if let Some(sort) = args.get("sort").and_then(Value::as_array) {
                    body["sort"] = Value::Array(sort.clone());
                }
                if let Some(automatic_fields) = args.get("automatic_fields").and_then(Value::as_bool) {
                    body["automatic_fields"] = Value::Bool(automatic_fields);
                }
                if let Some(page_size) = args.get("page_size").and_then(Value::as_u64) {
                    body["page_size"] = Value::Number(page_size.into());
                }
                if let Some(page_token) = args.get("page_token").and_then(Value::as_str) {
                    body["page_token"] = Value::String(page_token.to_string());
                }

                let payload = self
                    .client
                    .authed_request(Method::POST, &url, Some(body))
                    .await?;
                Ok(payload)
            }
            _ => anyhow::bail!("Unsupported action: {}", action),
        }
    }
}

#[async_trait]
impl Tool for FeishuBitableAppTableRecordTool {
    fn name(&self) -> &str {
        "feishu_bitable_app_table_record"
    }

    fn description(&self) -> &str {
        "Feishu/Lark Bitable record management using tenant_access_token. Actions: create, list, update, delete, batch_create, batch_update, batch_delete."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "enum": RECORD_ACTIONS },
                "app_token": { "type": "string" },
                "table_id": { "type": "string" },
                "record_id": { "type": "string" },
                "fields": { "type": "object", "additionalProperties": true },
                "records": { "type": "array", "items": { "type": "object" } },
                "record_ids": { "type": "array", "items": { "type": "string" } },
                "view_id": { "type": "string" },
                "field_names": { "type": "array", "items": { "type": "string" } },
                "filter": { "type": "object" },
                "sort": { "type": "array", "items": { "type": "object" } },
                "automatic_fields": { "type": "boolean" },
                "page_size": { "type": "integer" },
                "page_token": { "type": "string" }
            },
            "required": ["action", "app_token", "table_id"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let action = match args.get("action").and_then(Value::as_str) {
            Some(v) if !v.trim().is_empty() => v,
            _ => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing 'action' parameter".to_string()),
                });
            }
        };

        let operation = match action {
            "list" => ToolOperation::Read,
            _ => ToolOperation::Act,
        };
        if let Err(e) = self
            .security
            .enforce_tool_operation(operation, "feishu_bitable_app_table_record")
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e),
            });
        }

        match self.execute_action(action, &args).await {
            Ok(result) => Ok(ToolResult {
                success: true,
                output: result.to_string(),
                error: None,
            }),
            Err(err) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(crate::providers::sanitize_api_error(&err.to_string())),
            }),
        }
    }
}

async fn parse_json_or_empty(resp: reqwest::Response) -> anyhow::Result<Value> {
    let bytes = resp.bytes().await?;
    if bytes.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&bytes).or_else(|_| Ok(json!({ "raw": String::from_utf8_lossy(&bytes) })))
}

fn api_error_code(payload: &Value) -> Option<i64> {
    payload.get("code").and_then(Value::as_i64)
}

fn ensure_api_success(payload: &Value, context: &str) -> anyhow::Result<()> {
    let code = payload.get("code").and_then(Value::as_i64).unwrap_or(0);
    if code == 0 {
        return Ok(());
    }
    let msg = payload
        .get("msg")
        .and_then(Value::as_str)
        .unwrap_or("unknown error");
    anyhow::bail!("{context} api error: code={code}, msg={msg}, body={}", sanitize_api_json(payload));
}

fn sanitize_api_json(payload: &Value) -> Value {
    let mut v = payload.clone();
    if let Some(obj) = v.as_object_mut() {
        for key in ["tenant_access_token", "access_token", "refresh_token"] {
            if obj.contains_key(key) {
                obj.insert(key.to_string(), Value::String("<redacted>".to_string()));
            }
        }
    }
    v
}

fn extract_ttl_seconds(payload: &Value) -> u64 {
    payload
        .get("expire")
        .and_then(Value::as_u64)
        .or_else(|| payload.get("expire_in").and_then(Value::as_u64))
        .unwrap_or(DEFAULT_TOKEN_TTL.as_secs())
}

fn next_refresh_deadline(now: Instant, ttl_seconds: u64) -> Instant {
    let ttl = Duration::from_secs(ttl_seconds);
    let skew = TOKEN_REFRESH_SKEW.min(ttl / 2);
    now + ttl - skew
}
