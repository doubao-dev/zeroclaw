use crate::security::{policy::ToolOperation, SecurityPolicy};
use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use reqwest::Method;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const FEISHU_BASE_URL: &str = "https://open.feishu.cn/open-apis";
const LARK_BASE_URL: &str = "https://open.larksuite.com/open-apis";
const TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(120);
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(7200);
const INVALID_ACCESS_TOKEN_CODE: i64 = 99_991_663;

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

        let url = format!("{}/auth/v3/tenant_access_token/internal", self.api_base());
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

    async fn authed_api_request_with_query(
        &self,
        method: Method,
        url: &str,
        body: Option<Value>,
        query: Option<&[(&str, String)]>,
    ) -> anyhow::Result<Value> {
        let token = self.get_tenant_access_token().await?;
        let mut builder = self
            .client
            .request(method.clone(), url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json; charset=utf-8");

        if let Some(q) = query {
            builder = builder.query(q);
        }
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
                if let Some(q) = query {
                    builder = builder.query(q);
                }
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
                return Ok(payload);
            }

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
    pub fn new(
        app_id: String,
        app_secret: String,
        use_feishu: bool,
        security: Arc<SecurityPolicy>,
    ) -> Self {
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
                let app = payload.get("data").and_then(|v| v.get("app")).cloned();
                let app_token = extract_app_token(&payload)
                    .ok_or_else(|| anyhow::anyhow!("create response missing app_token"))?;
                let verified_app = self.verify_app_exists(&app_token).await?;
                Ok(json!({
                    "app": app,
                    "verified_via_api": true,
                    "verification_method": "bitable get",
                    "verification_note": "Do not use curl/http_request/web_fetch/browser tools on the returned Feishu URL to verify creation. This Bitable was already verified through the Feishu API.",
                    "verified_app": verified_app,
                }))
            }
            "get" => {
                let app_token = args
                    .get("app_token")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'app_token' parameter"))?;
                let url = format!("{}/bitable/v1/apps/{}", self.client.api_base(), app_token);
                let payload = self.client.authed_request(Method::GET, &url, None).await?;
                Ok(json!({ "app": payload.get("data").and_then(|v| v.get("app")).cloned() }))
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
                    anyhow::bail!(
                        "No fields provided for patch; supply 'name' and/or 'is_advanced'"
                    );
                }
                let url = format!("{}/bitable/v1/apps/{}", self.client.api_base(), app_token);
                let payload = self
                    .client
                    .authed_request(Method::PATCH, &url, Some(json!({ "app": app })))
                    .await?;
                Ok(json!({ "app": payload.get("data").and_then(|v| v.get("app")).cloned() }))
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
                let app = payload.get("data").and_then(|v| v.get("app")).cloned();
                let copied_app_token = extract_app_token(&payload)
                    .ok_or_else(|| anyhow::anyhow!("copy response missing app_token"))?;
                let verified_app = self.verify_app_exists(&copied_app_token).await?;
                Ok(json!({
                    "app": app,
                    "verified_via_api": true,
                    "verification_method": "bitable get",
                    "verification_note": "Do not use curl/http_request/web_fetch/browser tools on the returned Feishu URL to verify creation. This Bitable was already verified through the Feishu API.",
                    "verified_app": verified_app,
                }))
            }
            "set_permission" => {
                let app_token = args
                    .get("app_token")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'app_token' parameter"))?;
                let (member_type, member_id) = resolve_permission_member(args)?;
                let perm = required_drive_permission(args, "perm")?;
                let notify_lark = optional_bool(args, "notify_lark").unwrap_or(false);

                let member = self
                    .upsert_member_permission(
                        app_token,
                        &member_type,
                        &member_id,
                        perm,
                        notify_lark,
                    )
                    .await?;

                Ok(json!({
                    "success": true,
                    "app_token": app_token,
                    "member_type": member_type,
                    "member_id": member_id,
                    "perm": member
                        .get("perm")
                        .cloned()
                        .unwrap_or_else(|| Value::String(perm.to_string())),
                    "member": member,
                }))
            }
            "list" => {
                let folder_token = args.get("folder_token").and_then(Value::as_str);
                let page_size = args.get("page_size").and_then(Value::as_u64);
                let page_token = args.get("page_token").and_then(Value::as_str);

                let mut url = format!("{}/drive/v1/files", self.client.api_base());
                let mut sep = '?';
                if let Some(token) = folder_token {
                    url.push(sep);
                    sep = '&';
                    url.push_str(&format!("folder_token={}", urlencoding::encode(token)));
                }
                if let Some(size) = page_size {
                    url.push(sep);
                    sep = '&';
                    url.push_str(&format!("page_size={}", size));
                }
                if let Some(token) = page_token {
                    url.push(sep);
                    url.push_str(&format!("page_token={}", urlencoding::encode(token)));
                }

                let payload = self.client.authed_request(Method::GET, &url, None).await?;
                let files = payload
                    .get("data")
                    .and_then(|v| v.get("files"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let apps: Vec<Value> = files
                    .into_iter()
                    .filter(|v| v.get("type").and_then(Value::as_str) == Some("bitable"))
                    .collect();
                let has_more = payload
                    .get("data")
                    .and_then(|v| v.get("has_more"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let page_token = payload
                    .get("data")
                    .and_then(|v| v.get("page_token"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                Ok(json!({ "apps": apps, "has_more": has_more, "page_token": page_token }))
            }
            _ => anyhow::bail!("Unsupported action: {}", action),
        }
    }

    async fn upsert_member_permission(
        &self,
        app_token: &str,
        member_type: &str,
        member_id: &str,
        perm: &str,
        notify_lark: bool,
    ) -> anyhow::Result<Value> {
        let create_payload = self
            .create_permission_member(app_token, member_type, member_id, perm, notify_lark)
            .await?;
        if has_api_success_code(&create_payload) {
            return Ok(extract_permission_member(&create_payload));
        }
        if permission_member_already_exists(&create_payload) {
            let update_payload = self
                .update_permission_member(app_token, member_type, member_id, perm, notify_lark)
                .await?;
            ensure_api_success(&update_payload, "update permission member")?;
            return Ok(extract_permission_member(&update_payload));
        }
        ensure_api_success(&create_payload, "create permission member")?;
        Ok(extract_permission_member(&create_payload))
    }

    async fn create_permission_member(
        &self,
        app_token: &str,
        member_type: &str,
        member_id: &str,
        perm: &str,
        notify_lark: bool,
    ) -> anyhow::Result<Value> {
        let url = format!(
            "{}/drive/v1/permissions/{}/members",
            self.client.api_base(),
            app_token
        );
        let body = json!({
            "member_type": member_type,
            "member_id": member_id,
            "perm": perm
        });
        let query = [
            ("type", "bitable".to_string()),
            ("need_notification", notify_lark.to_string()),
        ];
        self.client
            .authed_api_request_with_query(Method::POST, &url, Some(body), Some(&query))
            .await
    }

    async fn update_permission_member(
        &self,
        app_token: &str,
        member_type: &str,
        member_id: &str,
        perm: &str,
        notify_lark: bool,
    ) -> anyhow::Result<Value> {
        let url = format!(
            "{}/drive/v1/permissions/{}/members/{}",
            self.client.api_base(),
            app_token,
            urlencoding::encode(member_id)
        );
        let body = json!({
            "token": app_token,
            "type": "bitable",
            "member_type": member_type,
            "member_id": member_id,
            "perm": perm,
            "notify_lark": notify_lark,
        });
        let query = [
            ("type", "bitable".to_string()),
            ("need_notification", notify_lark.to_string()),
        ];
        self.client
            .authed_api_request_with_query(Method::POST, &url, Some(body), Some(&query))
            .await
    }

    async fn verify_app_exists(&self, app_token: &str) -> anyhow::Result<Value> {
        let url = format!("{}/bitable/v1/apps/{}", self.client.api_base(), app_token);
        let payload = self.client.authed_request(Method::GET, &url, None).await?;
        Ok(payload
            .get("data")
            .and_then(|v| v.get("app"))
            .cloned()
            .unwrap_or_else(|| json!({})))
    }
}

#[async_trait]
impl Tool for FeishuBitableAppTool {
    fn name(&self) -> &str {
        "feishu_bitable_app"
    }

    fn description(&self) -> &str {
        "Feishu/Lark Bitable app management using tenant_access_token. Actions: create, get, list, patch, copy, set_permission.\n\nIMPORTANT RULES:\n1. Do NOT use curl, shell, http_request, web_fetch, or browser tools on returned Feishu/Lark bitable URLs to verify creation. Those URLs may redirect, require browser context, or return empty responses in headless environments.\n2. Create/copy results may already be verified through the Feishu API. If you need a follow-up check, use feishu_bitable_app get/list with the app_token instead of fetching the URL."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "create" },
                        "name": { "type": "string", "description": "多维表格名称" },
                        "folder_token": { "type": "string", "description": "所在文件夹 token（默认创建在我的空间）" }
                    },
                    "required": ["action", "name"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "get" },
                        "app_token": { "type": "string", "description": "多维表格的唯一标识 token" }
                    },
                    "required": ["action", "app_token"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "list" },
                        "folder_token": { "type": "string", "description": "文件夹 token（默认列出我的空间）" },
                        "page_size": { "type": "integer", "description": "每页数量，默认 50，最大 200" },
                        "page_token": { "type": "string", "description": "分页标记" }
                    },
                    "required": ["action"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "patch" },
                        "app_token": { "type": "string", "description": "多维表格 token" },
                        "name": { "type": "string", "description": "新的名称" },
                        "is_advanced": { "type": "boolean", "description": "是否开启高级权限" }
                    },
                    "required": ["action", "app_token"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "copy" },
                        "app_token": { "type": "string", "description": "源多维表格 token" },
                        "name": { "type": "string", "description": "新的名称" },
                        "folder_token": { "type": "string", "description": "目标文件夹 token" }
                    },
                    "required": ["action", "app_token", "name"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "set_permission" },
                        "app_token": { "type": "string", "description": "多维表格 token" },
                        "member_open_id": { "type": "string", "description": "协作者 open_id（兼容旧参数）" },
                        "member_email": { "type": "string", "description": "协作者邮箱（兼容旧参数）" },
                        "member_id": { "type": "string", "description": "协作者标识" },
                        "member_type": {
                            "type": "string",
                            "enum": ["openid", "email"],
                            "description": "协作者标识类型，默认按 member_open_id/member_email 推断"
                        },
                        "perm": {
                            "type": "string",
                            "enum": ["view", "edit", "full_access"],
                            "description": "权限级别"
                        },
                        "notify_lark": {
                            "type": "boolean",
                            "description": "是否通知协作者（默认 false）"
                        }
                    },
                    "required": ["action", "app_token", "member_open_id", "perm"],
                    "additionalProperties": false
                }
            ]
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
    pub fn new(
        app_id: String,
        app_secret: String,
        use_feishu: bool,
        security: Arc<SecurityPolicy>,
    ) -> Self {
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
                    anyhow::bail!("Missing table name; provide 'table.name'");
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
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables",
                    self.client.api_base(),
                    app_token
                );
                let payload = self
                    .client
                    .authed_request(Method::POST, &url, Some(json!({ "table": table })))
                    .await?;
                let data = payload.get("data").cloned().unwrap_or_else(|| json!({}));
                Ok(json!({
                    "table_id": data.get("table_id").cloned(),
                    "default_view_id": data.get("default_view_id").cloned(),
                    "field_id_list": data.get("field_id_list").cloned()
                }))
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
                let payload = self.client.authed_request(Method::GET, &url, None).await?;
                let data = payload.get("data").cloned().unwrap_or_else(|| json!({}));
                Ok(json!({
                    "tables": data.get("items").cloned(),
                    "has_more": data.get("has_more").cloned().unwrap_or(Value::Bool(false)),
                    "page_token": data.get("page_token").cloned()
                }))
            }
            "patch" => {
                let table_id = args
                    .get("table_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'table_id' parameter"))?;
                let name = args.get("name").and_then(Value::as_str).map(str::to_string);
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}",
                    self.client.api_base(),
                    app_token,
                    table_id
                );
                let payload = self
                    .client
                    .authed_request(Method::PATCH, &url, Some(json!({ "name": name })))
                    .await?;
                Ok(json!({ "name": payload.get("data").and_then(|v| v.get("name")).cloned() }))
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
                let _ = payload;
                Ok(json!({ "success": true }))
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
                Ok(
                    json!({ "table_ids": payload.get("data").and_then(|v| v.get("table_ids")).cloned() }),
                )
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
                let _ = payload;
                Ok(json!({ "success": true }))
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
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "create" },
                        "app_token": { "type": "string", "description": "多维表格 token" },
                        "table": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string", "description": "数据表名称" },
                                "default_view_name": { "type": "string", "description": "默认视图名称" },
                                "fields": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "field_name": { "type": "string" },
                                            "type": { "type": "integer" },
                                            "property": {}
                                        },
                                        "required": ["field_name", "type"],
                                        "additionalProperties": true
                                    }
                                }
                            },
                            "required": ["name"],
                            "additionalProperties": true
                        }
                    },
                    "required": ["action", "app_token", "table"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "list" },
                        "app_token": { "type": "string", "description": "多维表格 token" },
                        "page_size": { "type": "integer", "description": "每页数量，默认 50，最大 100" },
                        "page_token": { "type": "string", "description": "分页标记" }
                    },
                    "required": ["action", "app_token"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "patch" },
                        "app_token": { "type": "string", "description": "多维表格 token" },
                        "table_id": { "type": "string", "description": "数据表 ID" },
                        "name": { "type": "string", "description": "新的表名" }
                    },
                    "required": ["action", "app_token", "table_id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "delete" },
                        "app_token": { "type": "string", "description": "多维表格 token" },
                        "table_id": { "type": "string", "description": "数据表 ID" }
                    },
                    "required": ["action", "app_token", "table_id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "batch_create" },
                        "app_token": { "type": "string", "description": "多维表格 token" },
                        "tables": {
                            "type": "array",
                            "items": { "type": "object", "properties": { "name": { "type": "string" } }, "required": ["name"], "additionalProperties": false }
                        }
                    },
                    "required": ["action", "app_token", "tables"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "batch_delete" },
                        "app_token": { "type": "string", "description": "多维表格 token" },
                        "table_ids": { "type": "array", "items": { "type": "string" }, "description": "要删除的数据表 ID 列表" }
                    },
                    "required": ["action", "app_token", "table_ids"],
                    "additionalProperties": false
                }
            ]
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

pub struct FeishuBitableAppTableFieldTool {
    client: FeishuTenantClient,
    security: Arc<SecurityPolicy>,
}

impl FeishuBitableAppTableFieldTool {
    pub fn new(
        app_id: String,
        app_secret: String,
        use_feishu: bool,
        security: Arc<SecurityPolicy>,
    ) -> Self {
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
        let table_id = args
            .get("table_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Missing 'table_id' parameter"))?;

        match action {
            "create" => {
                let field_name = args
                    .get("field_name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'field_name' parameter"))?
                    .to_string();
                let field_type = args
                    .get("type")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'type' parameter"))?;

                let mut body = json!({
                    "field_name": field_name,
                    "type": field_type,
                });

                if let Some(property) = args.get("property") {
                    if !matches!(field_type, 7 | 15) {
                        body["property"] = property.clone();
                    }
                }

                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/fields",
                    self.client.api_base(),
                    app_token,
                    table_id
                );
                let payload = self
                    .client
                    .authed_request(Method::POST, &url, Some(body))
                    .await?;
                let field = payload
                    .get("data")
                    .and_then(|v| v.get("field"))
                    .cloned()
                    .or_else(|| payload.get("data").cloned());
                Ok(json!({ "field": field }))
            }
            "list" => {
                let view_id = args.get("view_id").and_then(Value::as_str);
                let page_size = args.get("page_size").and_then(Value::as_u64);
                let page_token = args.get("page_token").and_then(Value::as_str);

                let mut url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/fields",
                    self.client.api_base(),
                    app_token,
                    table_id
                );
                let mut sep = '?';
                if let Some(v) = view_id {
                    url.push(sep);
                    sep = '&';
                    url.push_str(&format!("view_id={}", urlencoding::encode(v)));
                }
                if let Some(size) = page_size {
                    url.push(sep);
                    sep = '&';
                    url.push_str(&format!("page_size={}", size));
                }
                if let Some(token) = page_token {
                    url.push(sep);
                    url.push_str(&format!("page_token={}", urlencoding::encode(token)));
                }

                let payload = self.client.authed_request(Method::GET, &url, None).await?;
                let data = payload.get("data").cloned().unwrap_or_else(|| json!({}));
                Ok(json!({
                    "fields": data.get("items").cloned(),
                    "has_more": data.get("has_more").cloned().unwrap_or(Value::Bool(false)),
                    "page_token": data.get("page_token").cloned()
                }))
            }
            "update" => {
                let field_id = args
                    .get("field_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'field_id' parameter"))?;

                let mut body = json!({});
                if let Some(name) = args.get("field_name").and_then(Value::as_str) {
                    body["field_name"] = Value::String(name.to_string());
                }
                let field_type = args.get("type").and_then(Value::as_i64);
                if let Some(ty) = field_type {
                    body["type"] = Value::Number(ty.into());
                }
                if let Some(property) = args.get("property") {
                    if !matches!(field_type, Some(7) | Some(15)) {
                        body["property"] = property.clone();
                    }
                }
                if body.as_object().map(|o| o.is_empty()).unwrap_or(true) {
                    anyhow::bail!("No fields provided for update; supply 'field_name' and/or 'type' and/or 'property'");
                }

                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/fields/{}",
                    self.client.api_base(),
                    app_token,
                    table_id,
                    field_id
                );
                let payload = self
                    .client
                    .authed_request(Method::PUT, &url, Some(body))
                    .await?;
                let field = payload
                    .get("data")
                    .and_then(|v| v.get("field"))
                    .cloned()
                    .or_else(|| payload.get("data").cloned());
                Ok(json!({ "field": field }))
            }
            "delete" => {
                let field_id = args
                    .get("field_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'field_id' parameter"))?;
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/fields/{}",
                    self.client.api_base(),
                    app_token,
                    table_id,
                    field_id
                );
                let payload = self
                    .client
                    .authed_request(Method::DELETE, &url, None)
                    .await?;
                let _ = payload;
                Ok(json!({ "success": true }))
            }
            _ => anyhow::bail!("Unsupported action: {}", action),
        }
    }
}

#[async_trait]
impl Tool for FeishuBitableAppTableFieldTool {
    fn name(&self) -> &str {
        "feishu_bitable_app_table_field"
    }

    fn description(&self) -> &str {
        "Feishu/Lark Bitable field management using tenant_access_token. Actions: create, list, update, delete."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "create" },
                        "app_token": { "type": "string", "description": "多维表格 token" },
                        "table_id": { "type": "string", "description": "数据表 ID" },
                        "field_name": { "type": "string", "description": "字段名称" },
                        "type": { "type": "integer", "description": "字段类型" },
                        "property": { "description": "字段属性配置（根据类型而定）" }
                    },
                    "required": ["action", "app_token", "table_id", "field_name", "type"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "list" },
                        "app_token": { "type": "string", "description": "多维表格 token" },
                        "table_id": { "type": "string", "description": "数据表 ID" },
                        "view_id": { "type": "string", "description": "视图 ID（可选）" },
                        "page_size": { "type": "integer", "description": "每页数量，默认 50，最大 100" },
                        "page_token": { "type": "string", "description": "分页标记" }
                    },
                    "required": ["action", "app_token", "table_id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "update" },
                        "app_token": { "type": "string", "description": "多维表格 token" },
                        "table_id": { "type": "string", "description": "数据表 ID" },
                        "field_id": { "type": "string", "description": "字段 ID" },
                        "field_name": { "type": "string", "description": "字段名（可选）" },
                        "type": { "type": "integer", "description": "字段类型（可选）" },
                        "property": { "description": "字段属性配置（可选）" }
                    },
                    "required": ["action", "app_token", "table_id", "field_id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "delete" },
                        "app_token": { "type": "string", "description": "多维表格 token" },
                        "table_id": { "type": "string", "description": "数据表 ID" },
                        "field_id": { "type": "string", "description": "字段 ID" }
                    },
                    "required": ["action", "app_token", "table_id", "field_id"],
                    "additionalProperties": false
                }
            ]
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
            .enforce_tool_operation(operation, "feishu_bitable_app_table_field")
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

pub struct FeishuBitableAppTableViewTool {
    client: FeishuTenantClient,
    security: Arc<SecurityPolicy>,
}

impl FeishuBitableAppTableViewTool {
    pub fn new(
        app_id: String,
        app_secret: String,
        use_feishu: bool,
        security: Arc<SecurityPolicy>,
    ) -> Self {
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
        let table_id = args
            .get("table_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Missing 'table_id' parameter"))?;

        match action {
            "create" => {
                let view_name = args
                    .get("view_name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'view_name' parameter"))?
                    .to_string();
                let view_type = args
                    .get("view_type")
                    .and_then(Value::as_str)
                    .unwrap_or("grid")
                    .to_string();
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/views",
                    self.client.api_base(),
                    app_token,
                    table_id
                );
                let payload = self
                    .client
                    .authed_request(
                        Method::POST,
                        &url,
                        Some(json!({ "view_name": view_name, "view_type": view_type })),
                    )
                    .await?;
                Ok(json!({ "view": payload.get("data").and_then(|v| v.get("view")).cloned() }))
            }
            "get" => {
                let view_id = args
                    .get("view_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'view_id' parameter"))?;
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/views/{}",
                    self.client.api_base(),
                    app_token,
                    table_id,
                    view_id
                );
                let payload = self.client.authed_request(Method::GET, &url, None).await?;
                Ok(json!({ "view": payload.get("data").and_then(|v| v.get("view")).cloned() }))
            }
            "list" => {
                let page_size = args.get("page_size").and_then(Value::as_u64);
                let page_token = args.get("page_token").and_then(Value::as_str);

                let mut url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/views",
                    self.client.api_base(),
                    app_token,
                    table_id
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

                let payload = self.client.authed_request(Method::GET, &url, None).await?;
                let data = payload.get("data").cloned().unwrap_or_else(|| json!({}));
                Ok(json!({
                    "views": data.get("items").cloned(),
                    "has_more": data.get("has_more").cloned().unwrap_or(Value::Bool(false)),
                    "page_token": data.get("page_token").cloned()
                }))
            }
            "patch" => {
                let view_id = args
                    .get("view_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'view_id' parameter"))?;
                let view_name = args
                    .get("view_name")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/views/{}",
                    self.client.api_base(),
                    app_token,
                    table_id,
                    view_id
                );
                let payload = self
                    .client
                    .authed_request(Method::PATCH, &url, Some(json!({ "view_name": view_name })))
                    .await?;
                Ok(json!({ "view": payload.get("data").and_then(|v| v.get("view")).cloned() }))
            }
            "delete" => {
                let view_id = args
                    .get("view_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'view_id' parameter"))?;
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/views/{}",
                    self.client.api_base(),
                    app_token,
                    table_id,
                    view_id
                );
                let payload = self
                    .client
                    .authed_request(Method::DELETE, &url, None)
                    .await?;
                let _ = payload;
                Ok(json!({ "success": true }))
            }
            _ => anyhow::bail!("Unsupported action: {}", action),
        }
    }
}

#[async_trait]
impl Tool for FeishuBitableAppTableViewTool {
    fn name(&self) -> &str {
        "feishu_bitable_app_table_view"
    }

    fn description(&self) -> &str {
        "Feishu/Lark Bitable view management using tenant_access_token. Actions: create, get, list, patch, delete."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "create" },
                        "app_token": { "type": "string" },
                        "table_id": { "type": "string" },
                        "view_name": { "type": "string" },
                        "view_type": { "type": "string", "enum": ["grid", "kanban", "gallery", "gantt", "form"] }
                    },
                    "required": ["action", "app_token", "table_id", "view_name"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "get" },
                        "app_token": { "type": "string" },
                        "table_id": { "type": "string" },
                        "view_id": { "type": "string" }
                    },
                    "required": ["action", "app_token", "table_id", "view_id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "list" },
                        "app_token": { "type": "string" },
                        "table_id": { "type": "string" },
                        "page_size": { "type": "integer" },
                        "page_token": { "type": "string" }
                    },
                    "required": ["action", "app_token", "table_id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "patch" },
                        "app_token": { "type": "string" },
                        "table_id": { "type": "string" },
                        "view_id": { "type": "string" },
                        "view_name": { "type": "string" }
                    },
                    "required": ["action", "app_token", "table_id", "view_id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "delete" },
                        "app_token": { "type": "string" },
                        "table_id": { "type": "string" },
                        "view_id": { "type": "string" }
                    },
                    "required": ["action", "app_token", "table_id", "view_id"],
                    "additionalProperties": false
                }
            ]
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
            .enforce_tool_operation(operation, "feishu_bitable_app_table_view")
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
    pub fn new(
        app_id: String,
        app_secret: String,
        use_feishu: bool,
        security: Arc<SecurityPolicy>,
    ) -> Self {
        Self {
            client: FeishuTenantClient::new(app_id, app_secret, use_feishu),
            security,
        }
    }

    fn reject_field_id_keys(fields: &serde_json::Map<String, Value>) -> anyhow::Result<()> {
        let mut bad: Vec<&str> = Vec::new();
        for key in fields.keys() {
            if key.starts_with("fld") {
                bad.push(key);
            }
        }
        if !bad.is_empty() {
            anyhow::bail!(
                "Invalid fields keys: {}. Use field_name keys (not field_id like fldXXXX).",
                bad.join(", ")
            );
        }
        Ok(())
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
                if args.get("records").is_some() {
                    return Ok(json!({
                        "error": "create action does not accept 'records' parameter",
                        "hint": "Use 'fields' for single record creation. For batch creation, use action: 'batch_create' with 'records' parameter."
                    }));
                }
                let fields = args
                    .get("fields")
                    .and_then(Value::as_object)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'fields' parameter"))?;
                if fields.is_empty() {
                    return Ok(json!({
                        "error": "fields is required and cannot be empty",
                        "hint": "create action requires 'fields' parameter, e.g. { \"field_name\": \"value\", ... }"
                    }));
                }
                Self::reject_field_id_keys(fields)?;
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
                Ok(json!({ "record": payload.get("data").and_then(|v| v.get("record")).cloned() }))
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
                    return Ok(json!({
                        "error": "fields is required and cannot be empty",
                        "hint": "update action requires 'fields' parameter, e.g. { \"field_name\": \"value\", ... }"
                    }));
                }
                Self::reject_field_id_keys(fields)?;
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
                Ok(json!({ "record": payload.get("data").and_then(|v| v.get("record")).cloned() }))
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
                let _ = payload;
                Ok(json!({ "success": true }))
            }
            "batch_create" => {
                let records = args
                    .get("records")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'records' parameter"))?;
                if records.is_empty() {
                    return Ok(json!({ "error": "records is required and cannot be empty" }));
                }
                if records.len() > 500 {
                    return Ok(
                        json!({ "error": "records count exceeds limit (maximum 500)", "received_count": records.len() }),
                    );
                }
                for record in records {
                    let fields = record
                        .get("fields")
                        .and_then(Value::as_object)
                        .ok_or_else(|| anyhow::anyhow!("record.fields must be an object"))?;
                    Self::reject_field_id_keys(fields)?;
                }
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
                Ok(
                    json!({ "records": payload.get("data").and_then(|v| v.get("records")).cloned() }),
                )
            }
            "batch_update" => {
                let records = args
                    .get("records")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'records' parameter"))?;
                if records.is_empty() {
                    return Ok(json!({ "error": "records is required and cannot be empty" }));
                }
                if records.len() > 500 {
                    return Ok(
                        json!({ "error": "records count exceeds limit (maximum 500)", "received_count": records.len() }),
                    );
                }
                for record in records {
                    let fields = record
                        .get("fields")
                        .and_then(Value::as_object)
                        .ok_or_else(|| anyhow::anyhow!("record.fields must be an object"))?;
                    Self::reject_field_id_keys(fields)?;
                }
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
                Ok(
                    json!({ "records": payload.get("data").and_then(|v| v.get("records")).cloned() }),
                )
            }
            "batch_delete" => {
                let record_ids = args
                    .get("record_ids")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow::anyhow!("Missing 'record_ids' parameter"))?;
                if record_ids.is_empty() {
                    return Ok(json!({ "error": "record_ids is required and cannot be empty" }));
                }
                if record_ids.len() > 500 {
                    return Ok(
                        json!({ "error": "record_ids count exceeds limit (maximum 500)", "received_count": record_ids.len() }),
                    );
                }
                let url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/records/batch_delete",
                    self.client.api_base(),
                    app_token,
                    table_id
                );
                let payload = self
                    .client
                    .authed_request(
                        Method::POST,
                        &url,
                        Some(json!({ "record_ids": record_ids })),
                    )
                    .await?;
                let _ = payload;
                Ok(json!({ "success": true }))
            }
            "list" => {
                let page_size = args.get("page_size").and_then(Value::as_u64);
                let page_token = args.get("page_token").and_then(Value::as_str);
                let mut url = format!(
                    "{}/bitable/v1/apps/{}/tables/{}/records/search?user_id_type=open_id",
                    self.client.api_base(),
                    app_token,
                    table_id
                );
                if let Some(size) = page_size {
                    url.push_str(&format!("&page_size={}", size));
                }
                if let Some(token) = page_token {
                    url.push_str(&format!("&page_token={}", urlencoding::encode(token)));
                }

                let mut body = json!({});
                if let Some(view_id) = args.get("view_id").and_then(Value::as_str) {
                    body["view_id"] = Value::String(view_id.to_string());
                }
                if let Some(field_names) = args.get("field_names").and_then(Value::as_array) {
                    body["field_names"] = Value::Array(field_names.clone());
                }
                if let Some(filter) = args.get("filter") {
                    let mut filter = filter.clone();
                    if let Some(conditions) =
                        filter.get_mut("conditions").and_then(Value::as_array_mut)
                    {
                        for cond in conditions.iter_mut() {
                            let op = cond.get("operator").and_then(Value::as_str);
                            if matches!(op, Some("isEmpty") | Some("isNotEmpty")) {
                                if cond.get("value").is_none() {
                                    cond.as_object_mut().map(|o| {
                                        o.insert("value".to_string(), Value::Array(vec![]))
                                    });
                                }
                            }
                        }
                    }
                    body["filter"] = filter;
                }
                if let Some(sort) = args.get("sort").and_then(Value::as_array) {
                    body["sort"] = Value::Array(sort.clone());
                }
                if let Some(automatic_fields) =
                    args.get("automatic_fields").and_then(Value::as_bool)
                {
                    body["automatic_fields"] = Value::Bool(automatic_fields);
                }
                let payload = self
                    .client
                    .authed_request(Method::POST, &url, Some(body))
                    .await?;
                let data = payload.get("data").cloned().unwrap_or_else(|| json!({}));
                Ok(json!({
                    "records": data.get("items").cloned(),
                    "has_more": data.get("has_more").cloned().unwrap_or(Value::Bool(false)),
                    "page_token": data.get("page_token").cloned(),
                    "total": data.get("total").cloned()
                }))
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
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "create" },
                        "app_token": { "type": "string", "description": "多维表格 token" },
                        "table_id": { "type": "string", "description": "数据表 ID" },
                        "fields": { "type": "object", "additionalProperties": true, "description": "记录字段（单条记录）。键为字段名。" }
                    },
                    "required": ["action", "app_token", "table_id", "fields"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "update" },
                        "app_token": { "type": "string" },
                        "table_id": { "type": "string" },
                        "record_id": { "type": "string", "description": "记录 ID" },
                        "fields": { "type": "object", "additionalProperties": true, "description": "要更新的字段（键为字段名）" }
                    },
                    "required": ["action", "app_token", "table_id", "record_id", "fields"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "delete" },
                        "app_token": { "type": "string" },
                        "table_id": { "type": "string" },
                        "record_id": { "type": "string" }
                    },
                    "required": ["action", "app_token", "table_id", "record_id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "batch_create" },
                        "app_token": { "type": "string" },
                        "table_id": { "type": "string" },
                        "records": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "fields": { "type": "object", "additionalProperties": true }
                                },
                                "required": ["fields"],
                                "additionalProperties": false
                            },
                            "description": "要批量创建的记录列表（最多 500 条）"
                        }
                    },
                    "required": ["action", "app_token", "table_id", "records"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "batch_update" },
                        "app_token": { "type": "string" },
                        "table_id": { "type": "string" },
                        "records": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "record_id": { "type": "string" },
                                    "fields": { "type": "object", "additionalProperties": true }
                                },
                                "required": ["record_id", "fields"],
                                "additionalProperties": false
                            },
                            "description": "要批量更新的记录列表（最多 500 条）"
                        }
                    },
                    "required": ["action", "app_token", "table_id", "records"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "batch_delete" },
                        "app_token": { "type": "string" },
                        "table_id": { "type": "string" },
                        "record_ids": { "type": "array", "items": { "type": "string" }, "description": "要删除的记录 ID 列表（最多 500 条）" }
                    },
                    "required": ["action", "app_token", "table_id", "record_ids"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "list" },
                        "app_token": { "type": "string" },
                        "table_id": { "type": "string" },
                        "view_id": { "type": "string", "description": "视图 ID（可选）" },
                        "field_names": { "type": "array", "items": { "type": "string" }, "description": "要返回的字段名列表（可选）" },
                        "filter": {
                            "type": "object",
                            "properties": {
                                "conjunction": { "type": "string", "enum": ["and", "or"] },
                                "conditions": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "field_name": { "type": "string" },
                                            "operator": { "type": "string" },
                                            "value": { "type": "array", "items": { "type": "string" } }
                                        },
                                        "required": ["field_name", "operator"],
                                        "additionalProperties": false
                                    }
                                }
                            },
                            "required": ["conjunction", "conditions"],
                            "additionalProperties": false
                        },
                        "sort": { "type": "array", "items": { "type": "object" } },
                        "automatic_fields": { "type": "boolean" },
                        "page_size": { "type": "integer" },
                        "page_token": { "type": "string" }
                    },
                    "required": ["action", "app_token", "table_id"],
                    "additionalProperties": false
                }
            ]
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
    serde_json::from_slice(&bytes)
        .or_else(|_| Ok(json!({ "raw": String::from_utf8_lossy(&bytes) })))
}

fn optional_bool(args: &Value, key: &str) -> Option<bool> {
    args.get(key).and_then(Value::as_bool)
}

fn resolve_permission_member(args: &Value) -> anyhow::Result<(String, String)> {
    let explicit_member_id = optional_string(args, "member_id");
    let explicit_member_type = optional_string(args, "member_type");
    let member_open_id = optional_string(args, "member_open_id");
    let member_email = optional_string(args, "member_email");

    if explicit_member_id.is_some() && member_open_id.is_some() {
        anyhow::bail!("Provide only one of 'member_id' or 'member_open_id'");
    }
    if explicit_member_id.is_some() && member_email.is_some() {
        anyhow::bail!("Provide only one of 'member_id' or 'member_email'");
    }
    if member_open_id.is_some() && member_email.is_some() {
        anyhow::bail!("Provide only one of 'member_open_id' or 'member_email'");
    }

    let member_type = match explicit_member_type.as_deref() {
        Some("openid") | None if member_open_id.is_some() => "openid".to_string(),
        Some("email") | None if member_email.is_some() => "email".to_string(),
        Some("openid") => "openid".to_string(),
        Some("email") => "email".to_string(),
        None => "openid".to_string(),
        Some(other) => anyhow::bail!(
            "Invalid 'member_type' value '{}'. Supported values: openid, email",
            other
        ),
    };

    let member_id = explicit_member_id
        .or(member_open_id)
        .or(member_email)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Missing permission member identifier. Provide 'member_id', 'member_open_id', or 'member_email'"
            )
        })?;

    Ok((member_type, member_id))
}

fn optional_string(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn required_drive_permission<'a>(args: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    let value = args
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Missing '{}' parameter", key))?;

    match value {
        "view" | "edit" | "full_access" => Ok(value),
        _ => anyhow::bail!(
            "Invalid '{}' value '{}'. Supported values: view, edit, full_access",
            key,
            value
        ),
    }
}

fn api_error_code(payload: &Value) -> Option<i64> {
    payload.get("code").and_then(Value::as_i64)
}

fn has_api_success_code(payload: &Value) -> bool {
    api_error_code(payload) == Some(0)
}

fn permission_member_already_exists(payload: &Value) -> bool {
    let msg = payload
        .get("msg")
        .or_else(|| payload.get("message"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();

    msg.contains("already exists")
        || msg.contains("already added")
        || msg.contains("member exists")
        || msg.contains("已存在")
}

fn extract_permission_member(payload: &Value) -> Value {
    payload
        .get("data")
        .and_then(|v| v.get("member"))
        .cloned()
        .unwrap_or_else(|| json!({}))
}

fn extract_app_token(payload: &Value) -> Option<String> {
    let data = payload.get("data")?;
    let app = data.get("app");
    [
        app.and_then(|v| v.get("app_token")),
        app.and_then(|v| v.get("token")),
        data.get("app_token"),
        data.get("token"),
    ]
    .into_iter()
    .flatten()
    .find_map(|v| v.as_str().map(str::to_string))
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
    anyhow::bail!(
        "{context} api error: code={code}, msg={msg}, body={}",
        sanitize_api_json(payload)
    );
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
