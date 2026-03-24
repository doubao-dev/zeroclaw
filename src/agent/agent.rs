use crate::agent::dispatcher::{
    NativeToolDispatcher, ParsedToolCall, ToolDispatcher, ToolExecutionResult, XmlToolDispatcher,
};
use crate::agent::loop_::detection::{DetectionVerdict, LoopDetectionConfig, LoopDetector};
use crate::agent::memory_loader::{DefaultMemoryLoader, MemoryLoader};
use crate::agent::prompt::{PromptContext, SystemPromptBuilder};
use crate::agent::research;
use crate::config::{Config, ResearchPhaseConfig};
use crate::memory::{self, Memory, MemoryCategory};
use crate::observability::{self, Observer, ObserverEvent};
use crate::providers::{self, ChatMessage, ChatRequest, ConversationMessage, Provider};
use crate::runtime;
use crate::security::SecurityPolicy;
use crate::tools::{self, Tool, ToolSpec};
use anyhow::Result;
use std::collections::HashMap;
use std::io::Write as IoWrite;
use std::sync::Arc;
use std::time::Instant;

const AUTOSAVE_MIN_MESSAGE_CHARS: usize = 20;

pub struct Agent {
    provider: Box<dyn Provider>,
    tools: Vec<Box<dyn Tool>>,
    tool_specs: Vec<ToolSpec>,
    memory: Arc<dyn Memory>,
    observer: Arc<dyn Observer>,
    prompt_builder: SystemPromptBuilder,
    tool_dispatcher: Box<dyn ToolDispatcher>,
    memory_loader: Box<dyn MemoryLoader>,
    config: crate::config::AgentConfig,
    model_name: String,
    temperature: f64,
    workspace_dir: std::path::PathBuf,
    identity_config: crate::config::IdentityConfig,
    skills: Vec<crate::skills::Skill>,
    skills_prompt_mode: crate::config::SkillsPromptInjectionMode,
    auto_save: bool,
    history: Vec<ConversationMessage>,
    classification_config: crate::config::QueryClassificationConfig,
    available_hints: Vec<String>,
    route_model_by_hint: HashMap<String, String>,
    research_config: ResearchPhaseConfig,
    turn_count_since_last_condense: usize,
}

pub struct AgentBuilder {
    provider: Option<Box<dyn Provider>>,
    tools: Option<Vec<Box<dyn Tool>>>,
    memory: Option<Arc<dyn Memory>>,
    observer: Option<Arc<dyn Observer>>,
    prompt_builder: Option<SystemPromptBuilder>,
    tool_dispatcher: Option<Box<dyn ToolDispatcher>>,
    memory_loader: Option<Box<dyn MemoryLoader>>,
    config: Option<crate::config::AgentConfig>,
    model_name: Option<String>,
    temperature: Option<f64>,
    workspace_dir: Option<std::path::PathBuf>,
    identity_config: Option<crate::config::IdentityConfig>,
    skills: Option<Vec<crate::skills::Skill>>,
    skills_prompt_mode: Option<crate::config::SkillsPromptInjectionMode>,
    auto_save: Option<bool>,
    classification_config: Option<crate::config::QueryClassificationConfig>,
    available_hints: Option<Vec<String>>,
    route_model_by_hint: Option<HashMap<String, String>>,
    research_config: Option<ResearchPhaseConfig>,
}

impl AgentBuilder {
    pub fn new() -> Self {
        Self {
            provider: None,
            tools: None,
            memory: None,
            observer: None,
            prompt_builder: None,
            tool_dispatcher: None,
            memory_loader: None,
            config: None,
            model_name: None,
            temperature: None,
            workspace_dir: None,
            identity_config: None,
            skills: None,
            skills_prompt_mode: None,
            auto_save: None,
            classification_config: None,
            available_hints: None,
            route_model_by_hint: None,
            research_config: None,
        }
    }

    pub fn provider(mut self, provider: Box<dyn Provider>) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn tools(mut self, tools: Vec<Box<dyn Tool>>) -> Self {
        self.tools = Some(tools);
        self
    }

    pub fn memory(mut self, memory: Arc<dyn Memory>) -> Self {
        self.memory = Some(memory);
        self
    }

    pub fn observer(mut self, observer: Arc<dyn Observer>) -> Self {
        self.observer = Some(observer);
        self
    }

    pub fn prompt_builder(mut self, prompt_builder: SystemPromptBuilder) -> Self {
        self.prompt_builder = Some(prompt_builder);
        self
    }

    pub fn tool_dispatcher(mut self, tool_dispatcher: Box<dyn ToolDispatcher>) -> Self {
        self.tool_dispatcher = Some(tool_dispatcher);
        self
    }

    pub fn memory_loader(mut self, memory_loader: Box<dyn MemoryLoader>) -> Self {
        self.memory_loader = Some(memory_loader);
        self
    }

    pub fn config(mut self, config: crate::config::AgentConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn model_name(mut self, model_name: String) -> Self {
        self.model_name = Some(model_name);
        self
    }

    pub fn temperature(mut self, temperature: f64) -> Self {
        self.temperature = Some(temperature);
        self
    }

    pub fn workspace_dir(mut self, workspace_dir: std::path::PathBuf) -> Self {
        self.workspace_dir = Some(workspace_dir);
        self
    }

    pub fn identity_config(mut self, identity_config: crate::config::IdentityConfig) -> Self {
        self.identity_config = Some(identity_config);
        self
    }

    pub fn skills(mut self, skills: Vec<crate::skills::Skill>) -> Self {
        self.skills = Some(skills);
        self
    }

    pub fn skills_prompt_mode(
        mut self,
        skills_prompt_mode: crate::config::SkillsPromptInjectionMode,
    ) -> Self {
        self.skills_prompt_mode = Some(skills_prompt_mode);
        self
    }

    pub fn auto_save(mut self, auto_save: bool) -> Self {
        self.auto_save = Some(auto_save);
        self
    }

    pub fn classification_config(
        mut self,
        classification_config: crate::config::QueryClassificationConfig,
    ) -> Self {
        self.classification_config = Some(classification_config);
        self
    }

    pub fn available_hints(mut self, available_hints: Vec<String>) -> Self {
        self.available_hints = Some(available_hints);
        self
    }

    pub fn route_model_by_hint(mut self, route_model_by_hint: HashMap<String, String>) -> Self {
        self.route_model_by_hint = Some(route_model_by_hint);
        self
    }

    pub fn research_config(mut self, research_config: ResearchPhaseConfig) -> Self {
        self.research_config = Some(research_config);
        self
    }

    pub fn build(self) -> Result<Agent> {
        let tools = self
            .tools
            .ok_or_else(|| anyhow::anyhow!("tools are required"))?;
        let tool_specs = tools.iter().map(|tool| tool.spec()).collect();

        Ok(Agent {
            provider: self
                .provider
                .ok_or_else(|| anyhow::anyhow!("provider is required"))?,
            tools,
            tool_specs,
            memory: self
                .memory
                .ok_or_else(|| anyhow::anyhow!("memory is required"))?,
            observer: self
                .observer
                .ok_or_else(|| anyhow::anyhow!("observer is required"))?,
            prompt_builder: self
                .prompt_builder
                .unwrap_or_else(SystemPromptBuilder::with_defaults),
            tool_dispatcher: self
                .tool_dispatcher
                .ok_or_else(|| anyhow::anyhow!("tool_dispatcher is required"))?,
            memory_loader: self
                .memory_loader
                .unwrap_or_else(|| Box::new(DefaultMemoryLoader::default())),
            config: self.config.unwrap_or_default(),
            model_name: crate::config::resolve_default_model_id(self.model_name.as_deref(), None),
            temperature: self.temperature.unwrap_or(0.7),
            workspace_dir: self
                .workspace_dir
                .unwrap_or_else(|| std::path::PathBuf::from(".")),
            identity_config: self.identity_config.unwrap_or_default(),
            skills: self.skills.unwrap_or_default(),
            skills_prompt_mode: self.skills_prompt_mode.unwrap_or_default(),
            auto_save: self.auto_save.unwrap_or(false),
            history: Vec::new(),
            classification_config: self.classification_config.unwrap_or_default(),
            available_hints: self.available_hints.unwrap_or_default(),
            route_model_by_hint: self.route_model_by_hint.unwrap_or_default(),
            research_config: self.research_config.unwrap_or_default(),
            turn_count_since_last_condense: 0,
        })
    }
}

impl Agent {
    pub fn builder() -> AgentBuilder {
        AgentBuilder::new()
    }

    pub fn tool_specs(&self) -> &[ToolSpec] {
        &self.tool_specs
    }

    pub fn history(&self) -> &[ConversationMessage] {
        &self.history
    }

    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    pub fn from_config(config: &Config) -> Result<Self> {
        if let Err(error) = crate::plugins::runtime::initialize_from_config(&config.plugins) {
            tracing::warn!("plugin registry initialization skipped: {error}");
        }

        let observer: Arc<dyn Observer> =
            Arc::from(observability::create_observer(&config.observability));
        let runtime: Arc<dyn runtime::RuntimeAdapter> =
            Arc::from(runtime::create_runtime(&config.runtime)?);
        let security = Arc::new(SecurityPolicy::from_config(
            &config.autonomy,
            &config.workspace_dir,
        ));

        let memory: Arc<dyn Memory> = Arc::from(memory::create_memory_with_storage_and_routes(
            &config.memory,
            &config.embedding_routes,
            Some(&config.storage.provider.config),
            &config.workspace_dir,
            config.api_key.as_deref(),
        )?);

        let composio_key = if config.composio.enabled {
            config.composio.api_key.as_deref()
        } else {
            None
        };
        let composio_entity_id = if config.composio.enabled {
            Some(config.composio.entity_id.as_str())
        } else {
            None
        };

        let tools = tools::all_tools_with_runtime(
            Arc::new(config.clone()),
            &security,
            runtime,
            memory.clone(),
            composio_key,
            composio_entity_id,
            &config.browser,
            &config.http_request,
            &config.web_fetch,
            &config.workspace_dir,
            &config.agents,
            config.api_key.as_deref(),
            config,
        );

        let provider_name = config.default_provider.as_deref().unwrap_or("openrouter");

        let model_name = crate::config::resolve_default_model_id(
            config.default_model.as_deref(),
            Some(provider_name),
        );

        let provider: Box<dyn Provider> = providers::create_routed_provider(
            provider_name,
            config.api_key.as_deref(),
            config.api_url.as_deref(),
            &config.reliability,
            &config.model_routes,
            &model_name,
        )?;

        let dispatcher_choice = config.agent.tool_dispatcher.as_str();
        let tool_dispatcher: Box<dyn ToolDispatcher> = match dispatcher_choice {
            "native" => Box::new(NativeToolDispatcher),
            "xml" => Box::new(XmlToolDispatcher),
            _ if provider.supports_native_tools() => Box::new(NativeToolDispatcher),
            _ => Box::new(XmlToolDispatcher),
        };

        let route_model_by_hint: HashMap<String, String> = config
            .model_routes
            .iter()
            .map(|route| (route.hint.clone(), route.model.clone()))
            .collect();
        let available_hints: Vec<String> = route_model_by_hint.keys().cloned().collect();

        Agent::builder()
            .provider(provider)
            .tools(tools)
            .memory(memory)
            .observer(observer)
            .tool_dispatcher(tool_dispatcher)
            .memory_loader(Box::new(DefaultMemoryLoader::new(
                5,
                config.memory.min_relevance_score,
            )))
            .prompt_builder(SystemPromptBuilder::with_defaults())
            .config(config.agent.clone())
            .model_name(model_name)
            .temperature(config.default_temperature)
            .workspace_dir(config.workspace_dir.clone())
            .classification_config(config.query_classification.clone())
            .available_hints(available_hints)
            .route_model_by_hint(route_model_by_hint)
            .identity_config(config.identity.clone())
            .skills(crate::skills::load_skills_with_config(
                &config.workspace_dir,
                config,
            ))
            .skills_prompt_mode(config.skills.prompt_injection_mode)
            .auto_save(config.memory.auto_save)
            .research_config(config.research.clone())
            .build()
    }

    fn trim_history(&mut self) {
        let max = self.config.max_history_messages;
        if self.history.len() <= max {
            return;
        }

        let mut system_messages = Vec::new();
        let mut other_messages = Vec::new();

        for msg in self.history.drain(..) {
            match &msg {
                ConversationMessage::Chat(chat) if chat.role == "system" => {
                    system_messages.push(msg);
                }
                _ => other_messages.push(msg),
            }
        }

        if other_messages.len() > max {
            let drop_count = other_messages.len() - max;
            other_messages.drain(0..drop_count);
        }

        self.history = system_messages;
        self.history.extend(other_messages);
    }

    fn build_system_prompt(&self) -> Result<String> {
        let instructions = self.tool_dispatcher.prompt_instructions(&self.tools);
        let ctx = PromptContext {
            workspace_dir: &self.workspace_dir,
            model_name: &self.model_name,
            tools: &self.tools,
            skills: &self.skills,
            skills_prompt_mode: self.skills_prompt_mode,
            identity_config: Some(&self.identity_config),
            dispatcher_instructions: &instructions,
        };
        self.prompt_builder.build(&ctx)
    }

    async fn execute_tool_call(&self, call: &ParsedToolCall) -> ToolExecutionResult {
        let start = Instant::now();

        let (result, success) = if let Some(tool) = self.tools.iter().find(|t| t.name() == call.name)
        {
            match tool.execute(call.arguments.clone()).await {
                Ok(r) => {
                    self.observer.record_event(&ObserverEvent::ToolCall {
                        tool: call.name.clone(),
                        duration: start.elapsed(),
                        success: r.success,
                    });
                    if r.success {
                        (r.output, true)
                    } else {
                        (format!("Error: {}", r.error.unwrap_or(r.output)), false)
                    }
                }
                Err(e) => {
                    self.observer.record_event(&ObserverEvent::ToolCall {
                        tool: call.name.clone(),
                        duration: start.elapsed(),
                        success: false,
                    });
                    (format!("Error executing {}: {e}", call.name), false)
                }
            }
        } else {
            (format!("Unknown tool: {}", call.name), false)
        };

        ToolExecutionResult {
            name: call.name.clone(),
            output: result,
            success,
            tool_call_id: call.tool_call_id.clone(),
        }
    }

    async fn execute_tools(&self, calls: &[ParsedToolCall]) -> Vec<ToolExecutionResult> {
        if !self.config.parallel_tools {
            let mut results = Vec::with_capacity(calls.len());
            for call in calls {
                results.push(self.execute_tool_call(call).await);
            }
            return results;
        }

        let futs: Vec<_> = calls
            .iter()
            .map(|call| self.execute_tool_call(call))
            .collect();
        futures_util::future::join_all(futs).await
    }

    fn classify_model(&self, user_message: &str) -> String {
        if let Some(decision) =
            super::classifier::classify_with_decision(&self.classification_config, user_message)
        {
            if self.available_hints.contains(&decision.hint) {
                let resolved_model = self
                    .route_model_by_hint
                    .get(&decision.hint)
                    .map(String::as_str)
                    .unwrap_or("unknown");
                tracing::info!(
                    target: "query_classification",
                    hint = decision.hint.as_str(),
                    model = resolved_model,
                    rule_priority = decision.priority,
                    message_length = user_message.len(),
                    "Classified message route"
                );
                return format!("hint:{}", decision.hint);
            }
        }
        self.model_name.clone()
    }

    pub async fn turn(&mut self, user_message: &str) -> Result<String> {
        self.turn_count_since_last_condense += 1;
        let user_message_clean = user_message.to_string();
        let mut user_message_for_history = user_message_clean.clone();

        if self.config.enable_memory_condense && self.config.condense_force_interval > 0 {
            let interval = self.config.condense_force_interval;
            if self.turn_count_since_last_condense >= interval {
                tracing::warn!("Force condensing memory due to turn limit");
                self.force_condense_history();
                self.turn_count_since_last_condense = 0;
                user_message_for_history = format!(
                    "[System: Previous context was hard-cleared due to length limit.]\n{}",
                    user_message_for_history
                );
            } else if self.turn_count_since_last_condense >= interval.saturating_sub(2) {
                let reminder = format!(
                    "\n\n[SYSTEM REMINDER: The turn budget before a forced context clear is nearly exhausted (in {} turns). \
                    Please consider invoking the 'self_memory_condense' tool soon to summarize and preserve key context before the budget is exceeded.]",
                    self.turn_count_since_last_condense
                );
                user_message_for_history.push_str(&reminder);
            }
        }

        if self.history.is_empty() {
            let system_prompt = self.build_system_prompt()?;
            self.history
                .push(ConversationMessage::Chat(ChatMessage::system(
                    system_prompt,
                )));
        } else if let Some(ConversationMessage::Chat(system_msg)) = self.history.first_mut() {
            if system_msg.role == "system" {
                crate::agent::prompt::refresh_prompt_datetime(&mut system_msg.content);
            }
        }

        if self.auto_save {
            let _ = self
                .memory
                .store(
                    "user_msg",
                    &user_message_clean,
                    MemoryCategory::Conversation,
                    None,
                )
                .await;
        }

        let context = self
            .memory_loader
            .load_context(self.memory.as_ref(), &user_message_clean)
            .await
            .unwrap_or_default();

        // ── Research Phase ──────────────────────────────────────────────
        // If enabled and triggered, run a focused research turn to gather
        // information before the main response.
        let research_context = if research::should_trigger(&self.research_config, user_message) {
            if self.research_config.show_progress {
                println!("[Research] Gathering information...");
            }

            match research::run_research_phase(
                &self.research_config,
                self.provider.as_ref(),
                &self.tools,
                user_message,
                &self.model_name,
                self.temperature,
                self.observer.clone(),
            )
            .await
            {
                Ok(result) => {
                    if self.research_config.show_progress {
                        println!(
                            "[Research] Complete: {} tool calls, {} chars context",
                            result.tool_call_count,
                            result.context.len()
                        );
                        for summary in &result.tool_summaries {
                            println!("  - {}: {}", summary.tool_name, summary.result_preview);
                        }
                    }
                    if result.context.is_empty() {
                        None
                    } else {
                        Some(result.context)
                    }
                }
                Err(e) => {
                    tracing::warn!("Research phase failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S %Z");
        let stamped_user_message = format!("[{now}] {user_message_for_history}");
        let enriched = match (&context, &research_context) {
            (c, Some(r)) if !c.is_empty() => {
                format!("{c}\n\n{r}\n\n{stamped_user_message}")
            }
            (_, Some(r)) => format!("{r}\n\n{stamped_user_message}"),
            (c, None) if !c.is_empty() => format!("{c}{stamped_user_message}"),
            _ => stamped_user_message,
        };

        self.history
            .push(ConversationMessage::Chat(ChatMessage::user(enriched)));

        let effective_model = self.classify_model(user_message);
        let loop_detection_config = LoopDetectionConfig {
            no_progress_threshold: self.config.loop_detection_no_progress_threshold,
            ping_pong_cycles: self.config.loop_detection_ping_pong_cycles,
            failure_streak_threshold: self.config.loop_detection_failure_streak,
        };
        let mut loop_detector = LoopDetector::new(loop_detection_config.clone());

        for iteration in 0..self.config.max_tool_iterations {
            let messages = self.tool_dispatcher.to_provider_messages(&self.history);
            let response = match self
                .provider
                .chat(
                    ChatRequest {
                        messages: &messages,
                        tools: if self.tool_dispatcher.should_send_tool_specs() {
                            Some(&self.tool_specs)
                        } else {
                            None
                        },
                    },
                    &effective_model,
                    self.temperature,
                )
                .await
            {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };

            let (text, calls) = self.tool_dispatcher.parse_response(&response);
            if calls.is_empty() {
                let final_text = if text.is_empty() {
                    response.text.unwrap_or_default()
                } else {
                    text
                };

                self.history
                    .push(ConversationMessage::Chat(ChatMessage::assistant(
                        final_text.clone(),
                    )));
                if self.auto_save && final_text.chars().count() >= AUTOSAVE_MIN_MESSAGE_CHARS {
                    let _ = self
                        .memory
                        .store(
                            "assistant_resp",
                            &final_text,
                            MemoryCategory::Conversation,
                            None,
                        )
                        .await;
                }
                self.trim_history();

                return Ok(final_text);
            }

            if !text.is_empty() {
                self.history
                    .push(ConversationMessage::Chat(ChatMessage::assistant(
                        text.clone(),
                    )));
                print!("{text}");
                let _ = std::io::stdout().flush();
            }

            self.history.push(ConversationMessage::AssistantToolCalls {
                text: response.text.clone(),
                tool_calls: response.tool_calls.clone(),
                reasoning_content: response.reasoning_content.clone(),
            });

            let has_memory_condense =
                calls.iter().any(|call| call.name == "self_memory_condense");
            let mut results = if has_memory_condense && calls.len() != 1 {
                calls
                    .iter()
                    .map(|call| {
                        let output = if call.name == "self_memory_condense" {
                            "Error: self_memory_condense must be called alone. Do not call any other tools in the same response.".to_string()
                        } else {
                            "Error: tool call skipped because self_memory_condense must be called alone."
                                .to_string()
                        };
                        ToolExecutionResult {
                            name: call.name.clone(),
                            output,
                            success: false,
                            tool_call_id: call.tool_call_id.clone(),
                        }
                    })
                    .collect()
            } else {
                self.execute_tools(&calls).await
            };

            let mut did_condense = false;
            if has_memory_condense && calls.len() == 1 {
                if let Some(result) = results.first_mut() {
                    if result.name == "self_memory_condense" && result.success {
                        if let Some(summary) = result.output.strip_prefix(
                            crate::tools::memory_condense::MEMORY_CONDENSE_PAYLOAD_PREFIX,
                        ) {
                            let mut new_history = Vec::new();

                            if let Some(sys_msg) = self.history.first().cloned() {
                                if matches!(sys_msg, ConversationMessage::Chat(ref c) if c.role == "system")
                                {
                                    new_history.push(sys_msg);
                                }
                            }

                            let condense_text = format!(
                                "<system_reminder>\n\
                                This session continues a previous conversation that lost its context due to length limits.\n\
                                You have proactively used MemoryCondense to summarize the past conversation.\n\
                                Your memory budget in this session is {} rounds, you should use the self_memory_condense tool again when approaching this limit.\n\
                                </system_reminder>\n\
                                \n\
                                The summary you provided to keep as context:\n\
                                {}\n\
                                \n\
                                Here is the user's most recent query context:\n\
                                {}",
                                self.config.condense_force_interval,
                                summary,
                                user_message_clean
                            );
                            new_history
                                .push(ConversationMessage::Chat(ChatMessage::user(condense_text)));

                            self.history = new_history;
                            self.turn_count_since_last_condense = 0;
                            loop_detector = LoopDetector::new(loop_detection_config.clone());
                            did_condense = true;
                        }
                    }
                }
            }

            if did_condense {
                continue;
            }

            // ── Loop detection: record calls ─────────────────────
            for (call, result) in calls.iter().zip(results.iter()) {
                let args_sig =
                    serde_json::to_string(&call.arguments).unwrap_or_else(|_| "{}".into());
                loop_detector.record_call(&call.name, &args_sig, &result.output, result.success);
            }

            let formatted = self.tool_dispatcher.format_results(&results);
            self.history.push(formatted);
            self.trim_history();

            match loop_detector.check() {
                DetectionVerdict::Continue => {}
                DetectionVerdict::InjectWarning(warning) => {
                    self.history
                        .push(ConversationMessage::Chat(ChatMessage::user(warning)));
                }
                DetectionVerdict::HardStop(reason) => {
                    anyhow::bail!(
                        "Agent stopped early due to detected loop pattern (iteration {}/{}): {}",
                        iteration + 1,
                        self.config.max_tool_iterations,
                        reason
                    );
                }
            }
    }

    anyhow::bail!(
        "Agent exceeded maximum tool iterations ({})",
        self.config.max_tool_iterations
    )
}

    fn force_condense_history(&mut self) {
        let sys_msgs: Vec<_> = self
            .history
            .iter()
            .filter(|m| matches!(m, ConversationMessage::Chat(c) if c.role == "system"))
            .cloned()
            .collect();

        let recent_msgs: Vec<_> = self.history.iter().rev().take(2).rev().cloned().collect();

        self.history = sys_msgs;

        let forced_condense_text = format!(
            "<system_reminder>\n\
            This session continues a previous conversation that lost its context due to length limits.\n\
            The context was FORCED CLEARED because the memory budget ({} rounds) was exceeded.\n\
            Please ensure you proactively use the 'self_memory_condense' tool in the future before hitting the limit.\n\
            </system_reminder>\n\
            \n\
            No summary was provided. The conversation continues from the last available messages.",
            self.config.condense_force_interval
        );

        self.history
            .push(ConversationMessage::Chat(ChatMessage::user(forced_condense_text)));
        self.history.extend(recent_msgs);
    }

    pub async fn run_single(&mut self, message: &str) -> Result<String> {
        self.turn(message).await
    }

    pub async fn run_interactive(&mut self) -> Result<()> {
        println!("🦀 ZeroClaw Interactive Mode");
        println!("Type /quit to exit.\n");

        let (tx, mut rx) = tokio::sync::mpsc::channel(32);
        let cli = crate::channels::CliChannel::new();

        let listen_handle = tokio::spawn(async move {
            let _ = crate::channels::Channel::listen(&cli, tx).await;
        });

        while let Some(msg) = rx.recv().await {
            let response = match self.turn(&msg.content).await {
                Ok(resp) => resp,
                Err(e) => {
                    eprintln!("\nError: {e}\n");
                    continue;
                }
            };
            println!("\n{response}\n");
        }

        listen_handle.abort();
        Ok(())
    }
}

pub async fn run(
    config: Config,
    message: Option<String>,
    provider_override: Option<String>,
    model_override: Option<String>,
    temperature: f64,
) -> Result<()> {
    let start = Instant::now();

    let mut effective_config = config;
    if let Some(p) = provider_override {
        effective_config.default_provider = Some(p);
    }
    if let Some(m) = model_override {
        effective_config.default_model = Some(m);
    }
    effective_config.default_temperature = temperature;

    let mut agent = Agent::from_config(&effective_config)?;

    let provider_name = effective_config
        .default_provider
        .as_deref()
        .unwrap_or("openrouter")
        .to_string();
    let model_name = effective_config
        .default_model
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            crate::config::default_model_fallback_for_provider(Some(&provider_name)).to_string()
        });

    agent.observer.record_event(&ObserverEvent::AgentStart {
        provider: provider_name.clone(),
        model: model_name.clone(),
    });

    if let Some(msg) = message {
        let response = agent.run_single(&msg).await?;
        println!("{response}");
    } else {
        agent.run_interactive().await?;
    }

    agent.observer.record_event(&ObserverEvent::AgentEnd {
        provider: provider_name,
        model: model_name,
        duration: start.elapsed(),
        tokens_used: None,
        cost_usd: None,
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use tempfile::TempDir;

    struct MockProvider {
        responses: Mutex<Vec<crate::providers::ChatResponse>>,
    }

    #[async_trait]
    impl Provider for MockProvider {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: f64,
        ) -> Result<String> {
            Ok("ok".into())
        }

        async fn chat(
            &self,
            _request: ChatRequest<'_>,
            _model: &str,
            _temperature: f64,
        ) -> Result<crate::providers::ChatResponse> {
            let mut guard = self.responses.lock();
            if guard.is_empty() {
                return Ok(crate::providers::ChatResponse {
                    text: Some("done".into()),
                    tool_calls: vec![],
                    usage: None,
                    reasoning_content: None,
                    quota_metadata: None,
                    stop_reason: None,
                    raw_stop_reason: None,
                });
            }
            Ok(guard.remove(0))
        }
    }

    struct ModelCaptureProvider {
        responses: Mutex<Vec<crate::providers::ChatResponse>>,
        seen_models: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl Provider for ModelCaptureProvider {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: f64,
        ) -> Result<String> {
            Ok("ok".into())
        }

        async fn chat(
            &self,
            _request: ChatRequest<'_>,
            model: &str,
            _temperature: f64,
        ) -> Result<crate::providers::ChatResponse> {
            self.seen_models.lock().push(model.to_string());
            let mut guard = self.responses.lock();
            if guard.is_empty() {
                return Ok(crate::providers::ChatResponse {
                    text: Some("done".into()),
                    tool_calls: vec![],
                    usage: None,
                    reasoning_content: None,
                    quota_metadata: None,
                    stop_reason: None,
                    raw_stop_reason: None,
                });
            }
            Ok(guard.remove(0))
        }
    }

    struct MockTool;

    #[async_trait]
    impl Tool for MockTool {
        fn name(&self) -> &str {
            "echo"
        }

        fn description(&self) -> &str {
            "echo"
        }

        fn parameters_schema(&self) -> serde_json::Value {
            serde_json::json!({"type": "object"})
        }

        async fn execute(&self, _args: serde_json::Value) -> Result<crate::tools::ToolResult> {
            Ok(crate::tools::ToolResult {
                success: true,
                output: "tool-out".into(),
                error: None,
            })
        }
    }

    #[tokio::test]
    async fn turn_without_tools_returns_text() {
        let provider = Box::new(MockProvider {
            responses: Mutex::new(vec![crate::providers::ChatResponse {
                text: Some("hello".into()),
                tool_calls: vec![],
                usage: None,
                reasoning_content: None,
                quota_metadata: None,
                stop_reason: None,
                raw_stop_reason: None,
            }]),
        });

        let memory_cfg = crate::config::MemoryConfig {
            backend: "none".into(),
            ..crate::config::MemoryConfig::default()
        };
        let mem: Arc<dyn Memory> = Arc::from(
            crate::memory::create_memory(&memory_cfg, std::path::Path::new("/tmp"), None)
                .expect("memory creation should succeed with valid config"),
        );

        let observer: Arc<dyn Observer> = Arc::from(crate::observability::NoopObserver {});
        let mut agent = Agent::builder()
            .provider(provider)
            .tools(vec![Box::new(MockTool)])
            .memory(mem)
            .observer(observer)
            .tool_dispatcher(Box::new(XmlToolDispatcher))
            .workspace_dir(std::path::PathBuf::from("/tmp"))
            .build()
            .expect("agent builder should succeed with valid config");

        let response = agent.turn("hi").await.unwrap();
        assert_eq!(response, "hello");
    }

    #[tokio::test]
    async fn turn_with_native_dispatcher_handles_tool_results_variant() {
        let provider = Box::new(MockProvider {
            responses: Mutex::new(vec![
                crate::providers::ChatResponse {
                    text: Some(String::new()),
                    tool_calls: vec![crate::providers::ToolCall {
                        id: "tc1".into(),
                        name: "echo".into(),
                        arguments: "{}".into(),
                    }],
                    usage: None,
                    reasoning_content: None,
                    quota_metadata: None,
                    stop_reason: None,
                    raw_stop_reason: None,
                },
                crate::providers::ChatResponse {
                    text: Some("done".into()),
                    tool_calls: vec![],
                    usage: None,
                    reasoning_content: None,
                    quota_metadata: None,
                    stop_reason: None,
                    raw_stop_reason: None,
                },
            ]),
        });

        let memory_cfg = crate::config::MemoryConfig {
            backend: "none".into(),
            ..crate::config::MemoryConfig::default()
        };
        let mem: Arc<dyn Memory> = Arc::from(
            crate::memory::create_memory(&memory_cfg, std::path::Path::new("/tmp"), None)
                .expect("memory creation should succeed with valid config"),
        );

        let observer: Arc<dyn Observer> = Arc::from(crate::observability::NoopObserver {});
        let mut agent = Agent::builder()
            .provider(provider)
            .tools(vec![Box::new(MockTool)])
            .memory(mem)
            .observer(observer)
            .tool_dispatcher(Box::new(NativeToolDispatcher))
            .workspace_dir(std::path::PathBuf::from("/tmp"))
            .build()
            .expect("agent builder should succeed with valid config");

        let response = agent.turn("hi").await.unwrap();
        assert_eq!(response, "done");
        assert!(agent
            .history()
            .iter()
            .any(|msg| matches!(msg, ConversationMessage::ToolResults(_))));
    }

    #[tokio::test]
    async fn turn_routes_with_hint_when_query_classification_matches() {
        let seen_models = Arc::new(Mutex::new(Vec::new()));
        let provider = Box::new(ModelCaptureProvider {
            responses: Mutex::new(vec![crate::providers::ChatResponse {
                text: Some("classified".into()),
                tool_calls: vec![],
                usage: None,
                reasoning_content: None,
                quota_metadata: None,
                stop_reason: None,
                raw_stop_reason: None,
            }]),
            seen_models: seen_models.clone(),
        });

        let memory_cfg = crate::config::MemoryConfig {
            backend: "none".into(),
            ..crate::config::MemoryConfig::default()
        };
        let mem: Arc<dyn Memory> = Arc::from(
            crate::memory::create_memory(&memory_cfg, std::path::Path::new("/tmp"), None)
                .expect("memory creation should succeed with valid config"),
        );

        let observer: Arc<dyn Observer> = Arc::from(crate::observability::NoopObserver {});
        let mut route_model_by_hint = HashMap::new();
        route_model_by_hint.insert("fast".to_string(), "anthropic/claude-haiku-4-5".to_string());
        let mut agent = Agent::builder()
            .provider(provider)
            .tools(vec![Box::new(MockTool)])
            .memory(mem)
            .observer(observer)
            .tool_dispatcher(Box::new(NativeToolDispatcher))
            .workspace_dir(std::path::PathBuf::from("/tmp"))
            .classification_config(crate::config::QueryClassificationConfig {
                enabled: true,
                rules: vec![crate::config::ClassificationRule {
                    hint: "fast".to_string(),
                    keywords: vec!["quick".to_string()],
                    patterns: vec![],
                    min_length: None,
                    max_length: None,
                    priority: 10,
                }],
            })
            .available_hints(vec!["fast".to_string()])
            .route_model_by_hint(route_model_by_hint)
            .build()
            .expect("agent builder should succeed with valid config");

        let response = agent.turn("quick summary please").await.unwrap();
        assert_eq!(response, "classified");
        let seen = seen_models.lock();
        assert_eq!(seen.as_slice(), &["hint:fast".to_string()]);
    }

    #[test]
    fn from_config_loads_plugin_declared_tools() {
        let tmp = TempDir::new().expect("temp dir");
        let plugin_dir = tmp.path().join("plugins");
        std::fs::create_dir_all(&plugin_dir).expect("create plugin dir");
        std::fs::create_dir_all(tmp.path().join("workspace")).expect("create workspace dir");

        std::fs::write(
            plugin_dir.join("agent_from_config.plugin.toml"),
            r#"
id = "agent-from-config"
version = "1.0.0"
module_path = "plugins/agent-from-config.wasm"
wit_packages = ["zeroclaw:tools@1.0.0"]

[[tools]]
name = "__agent_from_config_plugin_tool"
description = "plugin tool exposed for from_config tests"
"#,
        )
        .expect("write plugin manifest");

        let mut config = Config::default();
        config.workspace_dir = tmp.path().join("workspace");
        config.config_path = tmp.path().join("config.toml");
        config.default_provider = Some("ollama".to_string());
        config.memory.backend = "none".to_string();
        config.plugins = crate::config::PluginsConfig {
            enabled: true,
            load_paths: vec![plugin_dir.to_string_lossy().to_string()],
            ..crate::config::PluginsConfig::default()
        };

        let agent = Agent::from_config(&config).expect("agent from config should build");
        assert!(agent
            .tools
            .iter()
            .any(|tool| tool.name() == "__agent_from_config_plugin_tool"));
    }
}
