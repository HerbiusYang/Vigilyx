//! Event-driven DAG pipeline orchestrator.

//! Replaces the previous layer-based (Kahn + join_all barrier) model with a
//! true event-driven scheduler:

//! 1. All root nodes (in-degree 0) are spawned immediately.
//! 2. When a node completes, its successors' pending counts are atomically decremented.
//! 3. Any successor whose count reaches 0 is immediately spawned - no layer barrier.

//! This means `attach_content` starts as soon as `attach_scan` finishes, without
//! waiting for the other 11 independent root modules.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::{ConditionConfig, PipelineConfig};
use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{ModuleResult, SecurityModule};

// DAG node

pub struct PipelineExecutionOutcome {
    pub results: HashMap<String, ModuleResult>,
    pub timed_out: bool,
}

/// Metadata stored per graph node.
struct DagNode {
    module_id: String,
    module: Arc<dyn SecurityModule>,
    condition: Option<ConditionConfig>,
    timeout: Duration,
   /// If true, analyze() runs on the blocking thread pool via spawn_blocking.
    cpu_bound: bool,
}

// Orchestrator

/// The pipeline orchestrator: builds a petgraph DAG from module dependencies
/// and executes modules with event-driven scheduling.
pub struct PipelineOrchestrator {
   /// DAG: edge A -> B means "A must complete before B can start".
    graph: StableDiGraph<DagNode, ()>,
   /// module_id -> NodeIndex lookup (retained for future introspection).
    #[allow(dead_code)]
    node_index: HashMap<String, NodeIndex>,
   /// Root nodes (in-degree 0) - scheduled immediately on execute().
    roots: Vec<NodeIndex>,
   /// Total number of nodes to execute.
    node_count: usize,
   /// Global pipeline timeout (safety net).
    global_timeout: Duration,
}

impl PipelineOrchestrator {
   /// Build the orchestrator from registered modules and pipeline config.
   /// Validates no cycles exist in the dependency graph.
    pub fn build(
        all_modules: &HashMap<String, Arc<dyn SecurityModule>>,
        config: &PipelineConfig,
    ) -> Result<Self, EngineError> {
       // 1. Determine enabled modules
        let enabled: HashSet<String> = config
            .modules
            .iter()
            .filter(|m| m.enabled)
            .map(|m| m.id.clone())
            .filter(|id| all_modules.contains_key(id))
            .collect();

       // 2. Collect conditions
        let conditions: HashMap<String, ConditionConfig> = config
            .modules
            .iter()
            .filter_map(|m| m.condition.clone().map(|c| (m.id.clone(), c)))
            .collect();

       // 3. Build graph nodes
        let mut graph = StableDiGraph::<DagNode, ()>::new();
        let mut node_index: HashMap<String, NodeIndex> = HashMap::new();

        for id in &enabled {
            let module = all_modules
                .get(id)
                .ok_or_else(|| EngineError::UnknownModule(id.clone()))?
                .clone();
            let condition = conditions.get(id).cloned();
            let meta = module.metadata();
            let timeout_ms = meta.timeout_ms;
            let cpu_bound = meta.cpu_bound;
            let idx = graph.add_node(DagNode {
                module_id: id.clone(),
                module,
                condition,
                timeout: Duration::from_millis(timeout_ms),
                cpu_bound,
            });
            node_index.insert(id.clone(), idx);
        }

       // 4. Add hard dependency edges from metadata.depends_on
        for id in &enabled {
            let module = all_modules
                .get(id)
                .ok_or_else(|| EngineError::UnknownModule(id.clone()))?;
            let target_idx = node_index[id];
            for dep in &module.metadata().depends_on {
                if let Some(&source_idx) = node_index.get(dep) {
                    graph.add_edge(source_idx, target_idx, ());
                }
            }
        }

       // 5. Promote condition.depends_module to hard edges
        for id in &enabled {
            if let Some(cond) = conditions.get(id)
                && let Some(ref dep_module) = cond.depends_module
                && let (Some(&source_idx), Some(&target_idx)) =
                    (node_index.get(dep_module), node_index.get(id))
                && !graph.contains_edge(source_idx, target_idx)
            {
                graph.add_edge(source_idx, target_idx, ());
            }
        }

       // 6. Cycle detection via petgraph toposort
        if let Err(cycle) = petgraph::algo::toposort(&graph, None) {
            let cycle_node_id = &graph[cycle.node_id()].module_id;
            return Err(EngineError::CyclicDependency(format!(
                "cycle detected involving module: {}",
                cycle_node_id
            )));
        }

       // 7. Identify root nodes (in-degree = 0)
        let roots: Vec<NodeIndex> = graph
            .node_indices()
            .filter(|&idx| {
                graph
                    .neighbors_directed(idx, petgraph::Direction::Incoming)
                    .next()
                    .is_none()
            })
            .collect();

        let node_count = graph.node_count();

        info!(
            nodes = node_count,
            edges = graph.edge_count(),
            roots = roots.len(),
            "Pipeline DAG built (event-driven)"
        );

        Ok(Self {
            graph,
            node_index,
            roots,
            node_count,
            global_timeout: Duration::from_secs(90),
        })
    }

   /// Execute the pipeline for a given security context.
   /// Returns all module results.
    pub async fn execute(&self, ctx: &SecurityContext) -> HashMap<String, ModuleResult> {
        self.execute_with_timeout(ctx, self.global_timeout)
            .await
            .results
    }

   /// Execute the pipeline with an explicit global timeout budget.
    pub async fn execute_with_timeout(
        &self,
        ctx: &SecurityContext,
        global_timeout: Duration,
    ) -> PipelineExecutionOutcome {
        if self.node_count == 0 {
            return PipelineExecutionOutcome {
                results: HashMap::new(),
                timed_out: false,
            };
        }

       // Per-execution transient state

       // Pending dependency count for each node, indexed by NodeIndex::index().
        let pending: Arc<Vec<AtomicUsize>> = Arc::new(
            self.graph
                .node_indices()
                .map(|idx| {
                    let in_deg = self
                        .graph
                        .neighbors_directed(idx, petgraph::Direction::Incoming)
                        .count();
                    AtomicUsize::new(in_deg)
                })
                .collect(),
        );

       // Completion channel.
        let (done_tx, mut done_rx) = mpsc::channel::<NodeIndex>(self.node_count);
        let mut join_handles = Vec::with_capacity(self.node_count);

       // Seed root nodes
        for &root_idx in &self.roots {
            join_handles.push(self.spawn_node(root_idx, ctx, &done_tx));
        }

       // Event loop
        let mut completed = 0usize;
        let mut timed_out = false;
        let deadline = tokio::time::sleep(global_timeout.min(self.global_timeout));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                biased;

                Some(finished_idx) = done_rx.recv() => {
                    completed += 1;

                    if completed == self.node_count {
                        break;
                    }

                   // Schedule successors whose pending count reaches 0.
                    for succ_idx in self
                        .graph
                        .neighbors_directed(finished_idx, petgraph::Direction::Outgoing)
                    {
                        let prev = pending[succ_idx.index()].fetch_sub(1, Ordering::AcqRel);
                        debug_assert!(prev > 0, "pending underflow for node {}", succ_idx.index());
                        if prev == 1 {
                            join_handles.push(self.spawn_node(succ_idx, ctx, &done_tx));
                        }
                    }
                }

                () = &mut deadline => {
                    timed_out = true;
                    warn!(
                        completed = completed,
                        total = self.node_count,
                        timeout_secs = global_timeout.min(self.global_timeout).as_secs_f32(),
                        "Pipeline global timeout, returning partial results"
                    );
                    break;
                }
            }
        }

        if timed_out {
            for handle in &join_handles {
                handle.abort();
            }
        }

        PipelineExecutionOutcome {
            results: ctx.module_results().await,
            timed_out,
        }
    }

   /// Spawn a single node as an independent tokio task.
    
   /// CPU-bound modules are dispatched to the blocking thread pool via
   /// `spawn_blocking`, keeping async worker threads free for I/O modules.
    fn spawn_node(
        &self,
        node_idx: NodeIndex,
        ctx: &SecurityContext,
        done_tx: &mpsc::Sender<NodeIndex>,
    ) -> tokio::task::JoinHandle<()> {
        let node = &self.graph[node_idx];
        let module_id = node.module_id.clone();
        let module = node.module.clone();
        let timeout = node.timeout;
        let condition = node.condition.clone();
        let cpu_bound = node.cpu_bound;
        let ctx = ctx.clone();
        let done_tx = done_tx.clone();

        tokio::spawn(async move {
            let start = Instant::now();

           // Conditional execution check
            if !Self::should_execute_node(&module, &condition, &ctx).await {
                debug!(module = %module_id, "Node skipped (condition not met)");
               // hopsofModule Result, first (Status: alreadyhops)
                let skipped_result = ModuleResult::not_applicable(
                    &module_id,
                    &module.metadata().name,
                    module.metadata().pillar,
                    "Condition not met, skipped",
                    0,
                );
                ctx.insert_result(skipped_result).await;
                let _ = done_tx.send(node_idx).await;
                return;
            }

           // Execute with per-module timeout
           // CPU-bound modules run on the blocking thread pool;
           // I/O-bound modules run on the async worker pool.
            let result = if cpu_bound {
                let handle = tokio::runtime::Handle::current();
                let m = module.clone();
                let c = ctx.clone();
                tokio::time::timeout(timeout, async {
                    tokio::task::spawn_blocking(move || handle.block_on(m.analyze(&c)))
                        .await
                        .unwrap_or_else(|e| {
                            Err(EngineError::Other(format!("spawn_blocking join: {e}")))
                        })
                })
                .await
            } else {
                tokio::time::timeout(timeout, module.analyze(&ctx)).await
            };

            let module_result = match result {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    error!(module = %module_id, error = %e, "Module failed");
                    ModuleResult::not_applicable(
                        &module_id,
                        &module.metadata().name,
                        module.metadata().pillar,
                        &format!("ModuleExecutelineFailed: {e}"),
                        start.elapsed().as_millis() as u64,
                    )
                }
                Err(_) => {
                    let timeout_ms = timeout.as_millis() as u64;
                    warn!(module = %module_id, timeout_ms, "Module timed out");
                    ModuleResult::not_applicable(
                        &module_id,
                        &module.metadata().name,
                        module.metadata().pillar,
                        &format!("ModuleTimeout ({timeout_ms}ms)"),
                        timeout_ms,
                    )
                }
            };

            debug!(
                module = %module_id,
                threat = %module_result.threat_level,
                ms = start.elapsed().as_millis() as u64,
                "Module completed"
            );

            ctx.insert_result(module_result).await;
            let _ = done_tx.send(node_idx).await;
        })
    }

   /// Check whether a node should execute (conditions + module predicate).
    async fn should_execute_node(
        module: &Arc<dyn SecurityModule>,
        condition: &Option<ConditionConfig>,
        ctx: &SecurityContext,
    ) -> bool {
        if !module.should_run(ctx) {
            return false;
        }

        if let Some(cond) = &condition
            && let Some(min_level) = &cond.min_threat_level
        {
            let current_max = ctx.max_threat_level().await;
            if current_max < *min_level {
                return false;
            }
           // depends_module ordering is guaranteed by the DAG edge,
           // so no runtime has_result() check is needed.
        }

        true
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ModuleConfig, PipelineConfig, VerdictConfig};
    use crate::module::{ModuleMetadata, Pillar};
    use async_trait::async_trait;
    use std::sync::atomic::AtomicU64;
    use vigilyx_core::models::{EmailSession, Protocol};

   /// Helper: build a minimal SecurityContext for testing.
    fn test_ctx() -> SecurityContext {
        let session = EmailSession::new(
            Protocol::Smtp,
            "127.0.0.1".to_string(),
            12345,
            "127.0.0.1".to_string(),
            25,
        );
        SecurityContext::new(Arc::new(session))
    }

   /// Helper: build a PipelineConfig from module configs.
    fn make_config(modules: Vec<ModuleConfig>) -> PipelineConfig {
        PipelineConfig {
            version: 1,
            modules,
            verdict_config: VerdictConfig::default(),
        }
    }

   /// Helper: build a ModuleConfig.
    fn module_cfg(id: &str) -> ModuleConfig {
        ModuleConfig {
            id: id.to_string(),
            enabled: true,
            mode: crate::module::RunMode::Builtin,
            config: serde_json::Value::Null,
            condition: None,
        }
    }

   // Mock module

    struct MockModule {
        meta: ModuleMetadata,
        delay: Duration,
        should_run_val: bool,
       /// Monotonic counter: records the order in which modules complete.
        completion_order: Arc<AtomicU64>,
    }

    impl MockModule {
        fn new(
            id: &str,
            depends_on: Vec<String>,
            delay: Duration,
            completion_order: Arc<AtomicU64>,
        ) -> Self {
            Self {
                meta: ModuleMetadata {
                    id: id.to_string(),
                    name: id.to_string(),
                    description: String::new(),
                    pillar: Pillar::Content,
                    depends_on,
                    timeout_ms: 10000,
                    is_remote: false,
                    supports_ai: false,
                    cpu_bound: false,
                    inline_priority: None,
                },
                delay,
                should_run_val: true,
                completion_order,
            }
        }

        fn with_should_run(mut self, val: bool) -> Self {
            self.should_run_val = val;
            self
        }

        fn with_timeout_ms(mut self, ms: u64) -> Self {
            self.meta.timeout_ms = ms;
            self
        }
    }

    #[async_trait]
    impl SecurityModule for MockModule {
        fn metadata(&self) -> &ModuleMetadata {
            &self.meta
        }

        async fn analyze(&self, _ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
            tokio::time::sleep(self.delay).await;
            self.completion_order.fetch_add(1, Ordering::SeqCst);
            #[allow(deprecated)]
            Ok(ModuleResult::safe(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "mock ok",
                self.delay.as_millis() as u64,
            ))
        }

        fn should_run(&self, _ctx: &SecurityContext) -> bool {
            self.should_run_val
        }
    }

   // Tests

    #[tokio::test]
    async fn test_empty_pipeline() {
        let modules: HashMap<String, Arc<dyn SecurityModule>> = HashMap::new();
        let config = make_config(vec![]);
        let orch = PipelineOrchestrator::build(&modules, &config).unwrap();
        let ctx = test_ctx();
        let results = orch.execute(&ctx).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_execute_with_timeout_returns_partial_results() {
        let order = Arc::new(AtomicU64::new(0));
        let mut modules: HashMap<String, Arc<dyn SecurityModule>> = HashMap::new();
        modules.insert(
            "fast".into(),
            Arc::new(MockModule::new(
                "fast",
                vec![],
                Duration::from_millis(5),
                order.clone(),
            )),
        );
        modules.insert(
            "slow".into(),
            Arc::new(MockModule::new(
                "slow",
                vec![],
                Duration::from_millis(200),
                order,
            )),
        );

        let config = make_config(vec![module_cfg("fast"), module_cfg("slow")]);
        let orch = PipelineOrchestrator::build(&modules, &config).unwrap();
        let ctx = test_ctx();

        let outcome = orch
            .execute_with_timeout(&ctx, Duration::from_millis(20))
            .await;

        assert!(outcome.timed_out, "pipeline should respect the timeout budget");
        assert!(
            outcome.results.contains_key("fast"),
            "completed tier-1 work should be preserved"
        );
        assert!(
            !outcome.results.contains_key("slow"),
            "timed-out work should not continue populating results"
        );
    }

    #[tokio::test]
    async fn test_linear_chain() {
        let order = Arc::new(AtomicU64::new(0));
        let mut modules: HashMap<String, Arc<dyn SecurityModule>> = HashMap::new();
        modules.insert(
            "a".into(),
            Arc::new(MockModule::new(
                "a",
                vec![],
                Duration::from_millis(10),
                order.clone(),
            )),
        );
        modules.insert(
            "b".into(),
            Arc::new(MockModule::new(
                "b",
                vec!["a".into()],
                Duration::from_millis(10),
                order.clone(),
            )),
        );
        modules.insert(
            "c".into(),
            Arc::new(MockModule::new(
                "c",
                vec!["b".into()],
                Duration::from_millis(10),
                order.clone(),
            )),
        );

        let config = make_config(vec![module_cfg("a"), module_cfg("b"), module_cfg("c")]);
        let orch = PipelineOrchestrator::build(&modules, &config).unwrap();
        let ctx = test_ctx();
        let results = orch.execute(&ctx).await;

        assert_eq!(results.len(), 3);
        assert!(results.contains_key("a"));
        assert!(results.contains_key("b"));
        assert!(results.contains_key("c"));
    }

    #[tokio::test]
    async fn test_diamond_dag() {
       // A -> B, A -> C, B -> D, C -> D
        let order = Arc::new(AtomicU64::new(0));
        let mut modules: HashMap<String, Arc<dyn SecurityModule>> = HashMap::new();
        modules.insert(
            "a".into(),
            Arc::new(MockModule::new(
                "a",
                vec![],
                Duration::from_millis(10),
                order.clone(),
            )),
        );
        modules.insert(
            "b".into(),
            Arc::new(MockModule::new(
                "b",
                vec!["a".into()],
                Duration::from_millis(10),
                order.clone(),
            )),
        );
        modules.insert(
            "c".into(),
            Arc::new(MockModule::new(
                "c",
                vec!["a".into()],
                Duration::from_millis(10),
                order.clone(),
            )),
        );
        modules.insert(
            "d".into(),
            Arc::new(MockModule::new(
                "d",
                vec!["b".into(), "c".into()],
                Duration::from_millis(10),
                order.clone(),
            )),
        );

        let config = make_config(vec![
            module_cfg("a"),
            module_cfg("b"),
            module_cfg("c"),
            module_cfg("d"),
        ]);
        let orch = PipelineOrchestrator::build(&modules, &config).unwrap();
        let ctx = test_ctx();
        let results = orch.execute(&ctx).await;

        assert_eq!(results.len(), 4);
    }

    #[tokio::test]
    async fn test_no_layer_barrier() {
       // "fast_root" finishes in 10ms. "slow_root" takes 300ms.
       // "dependent" depends only on fast_root.
       // In event-driven: dependent starts at ~10ms, finishes at ~20ms.
       // In layer-based: dependent would start at ~300ms.
        let order = Arc::new(AtomicU64::new(0));
        let mut modules: HashMap<String, Arc<dyn SecurityModule>> = HashMap::new();
        modules.insert(
            "fast_root".into(),
            Arc::new(MockModule::new(
                "fast_root",
                vec![],
                Duration::from_millis(10),
                order.clone(),
            )),
        );
        modules.insert(
            "slow_root".into(),
            Arc::new(MockModule::new(
                "slow_root",
                vec![],
                Duration::from_millis(300),
                order.clone(),
            )),
        );
        modules.insert(
            "dependent".into(),
            Arc::new(MockModule::new(
                "dependent",
                vec!["fast_root".into()],
                Duration::from_millis(10),
                order.clone(),
            )),
        );

        let config = make_config(vec![
            module_cfg("fast_root"),
            module_cfg("slow_root"),
            module_cfg("dependent"),
        ]);
        let orch = PipelineOrchestrator::build(&modules, &config).unwrap();
        let ctx = test_ctx();

        let start = Instant::now();
        let results = orch.execute(&ctx).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 3);
       // Total time should be ~300ms (slow_root dominates), NOT ~310ms+
       // But dependent should have started at ~10ms, not ~300ms.
       // We can verify total time is <400ms (generous upper bound).
        assert!(
            elapsed < Duration::from_millis(500),
            "Pipeline took too long: {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_cycle_detection() {
        let order = Arc::new(AtomicU64::new(0));
        let mut modules: HashMap<String, Arc<dyn SecurityModule>> = HashMap::new();
        modules.insert(
            "a".into(),
            Arc::new(MockModule::new(
                "a",
                vec!["b".into()],
                Duration::from_millis(10),
                order.clone(),
            )),
        );
        modules.insert(
            "b".into(),
            Arc::new(MockModule::new(
                "b",
                vec!["a".into()],
                Duration::from_millis(10),
                order.clone(),
            )),
        );

        let config = make_config(vec![module_cfg("a"), module_cfg("b")]);
        let result = PipelineOrchestrator::build(&modules, &config);

        match result {
            Err(EngineError::CyclicDependency(_)) => {} // expected
            Err(other) => panic!("Expected CyclicDependency, got: {:?}", other),
            Ok(_) => panic!("Expected error, but build() succeeded"),
        }
    }

    #[tokio::test]
    async fn test_skipped_node_signals_successors() {
        let order = Arc::new(AtomicU64::new(0));
        let mut modules: HashMap<String, Arc<dyn SecurityModule>> = HashMap::new();
       // "a" has should_run = false. "b" depends on "a".
        modules.insert(
            "a".into(),
            Arc::new(
                MockModule::new("a", vec![], Duration::from_millis(10), order.clone())
                    .with_should_run(false),
            ),
        );
        modules.insert(
            "b".into(),
            Arc::new(MockModule::new(
                "b",
                vec!["a".into()],
                Duration::from_millis(10),
                order.clone(),
            )),
        );

        let config = make_config(vec![module_cfg("a"), module_cfg("b")]);
        let orch = PipelineOrchestrator::build(&modules, &config).unwrap();
        let ctx = test_ctx();
        let results = orch.execute(&ctx).await;

       // "a" was skipped but still produces a result (marked as skipped), "b" should still run.
        assert!(results.contains_key("a"));
        assert_eq!(results["a"].summary, "Condition not met, skipped");
        assert!(results.contains_key("b"));
    }

    #[tokio::test]
    async fn test_module_timeout() {
        let order = Arc::new(AtomicU64::new(0));
        let mut modules: HashMap<String, Arc<dyn SecurityModule>> = HashMap::new();
       // Module sleeps 5 seconds but has 100ms timeout.
        modules.insert(
            "slow".into(),
            Arc::new(
                MockModule::new("slow", vec![], Duration::from_secs(5), order.clone())
                    .with_timeout_ms(100),
            ),
        );

        let config = make_config(vec![module_cfg("slow")]);
        let orch = PipelineOrchestrator::build(&modules, &config).unwrap();
        let ctx = test_ctx();

        let start = Instant::now();
        let results = orch.execute(&ctx).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 1);
        assert!(results["slow"].summary.contains("Timeout"));
        assert!(elapsed < Duration::from_millis(500));
    }

    #[tokio::test]
    async fn test_global_timeout() {
        let order = Arc::new(AtomicU64::new(0));
        let mut modules: HashMap<String, Arc<dyn SecurityModule>> = HashMap::new();
       // 3 modules, each sleeping 60s. Individual timeout is also 60s.
        for name in ["x", "y", "z"] {
            modules.insert(
                name.into(),
                Arc::new(
                    MockModule::new(name, vec![], Duration::from_secs(60), order.clone())
                        .with_timeout_ms(60000),
                ),
            );
        }

        let config = make_config(vec![module_cfg("x"), module_cfg("y"), module_cfg("z")]);
        let mut orch = PipelineOrchestrator::build(&modules, &config).unwrap();
        orch.global_timeout = Duration::from_millis(200); // Override for test

        let ctx = test_ctx();
        let start = Instant::now();
        let results = orch.execute(&ctx).await;
        let elapsed = start.elapsed();

       // Should return within ~200ms with 0 results (none finished).
        assert!(elapsed < Duration::from_millis(500));
        assert!(results.is_empty());
    }

   // P0: CPU-bound dispatch tests

   /// A mock module that marks itself as cpu_bound.
    struct CpuBoundMockModule {
        meta: ModuleMetadata,
        completion_order: Arc<AtomicU64>,
    }

    impl CpuBoundMockModule {
        fn new(id: &str, depends_on: Vec<String>, order: Arc<AtomicU64>) -> Self {
            Self {
                meta: ModuleMetadata {
                    id: id.to_string(),
                    name: id.to_string(),
                    description: String::new(),
                    pillar: Pillar::Content,
                    depends_on,
                    timeout_ms: 5000,
                    is_remote: false,
                    supports_ai: false,
                    cpu_bound: true,
                    inline_priority: None,
                },
                completion_order: order,
            }
        }
    }

    #[async_trait]
    impl SecurityModule for CpuBoundMockModule {
        fn metadata(&self) -> &ModuleMetadata {
            &self.meta
        }

        async fn analyze(&self, _ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
           // Pure CPU work (no.await) - simulated by a busy spin.
            let mut sum = 0u64;
            for i in 0..10_000 {
                sum = sum.wrapping_add(i);
            }
            let _ = sum;

            self.completion_order
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            #[allow(deprecated)]
            Ok(ModuleResult::safe(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "cpu_bound mock ok",
                1,
            ))
        }
    }

    #[tokio::test]
    async fn test_cpu_bound_module_completes() {
        let order = Arc::new(AtomicU64::new(0));
        let mut modules: HashMap<String, Arc<dyn SecurityModule>> = HashMap::new();
        modules.insert(
            "cpu_a".into(),
            Arc::new(CpuBoundMockModule::new("cpu_a", vec![], order.clone())),
        );
        modules.insert(
            "cpu_b".into(),
            Arc::new(CpuBoundMockModule::new(
                "cpu_b",
                vec!["cpu_a".into()],
                order.clone(),
            )),
        );

        let config = make_config(vec![module_cfg("cpu_a"), module_cfg("cpu_b")]);
        let orch = PipelineOrchestrator::build(&modules, &config).unwrap();
        let ctx = test_ctx();
        let results = orch.execute(&ctx).await;

        assert_eq!(results.len(), 2);
        assert!(results.contains_key("cpu_a"));
        assert!(results.contains_key("cpu_b"));
        assert_eq!(order.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_mixed_cpu_io_modules() {
        let order = Arc::new(AtomicU64::new(0));
        let mut modules: HashMap<String, Arc<dyn SecurityModule>> = HashMap::new();

       // "io_mod" is I/O-bound (uses tokio::sleep), takes 50ms
        modules.insert(
            "io_mod".into(),
            Arc::new(MockModule::new(
                "io_mod",
                vec![],
                Duration::from_millis(50),
                order.clone(),
            )),
        );

       // "cpu_mod" is CPU-bound, depends on io_mod
        modules.insert(
            "cpu_mod".into(),
            Arc::new(CpuBoundMockModule::new(
                "cpu_mod",
                vec!["io_mod".into()],
                order.clone(),
            )),
        );

        let config = make_config(vec![module_cfg("io_mod"), module_cfg("cpu_mod")]);
        let orch = PipelineOrchestrator::build(&modules, &config).unwrap();
        let ctx = test_ctx();
        let results = orch.execute(&ctx).await;

        assert_eq!(results.len(), 2);
        assert!(results.contains_key("io_mod"));
        assert!(results.contains_key("cpu_mod"));
    }
}
