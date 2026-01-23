//! Example: Simple Hermes Rule Evaluation Pipeline
//!
//! Demonstrates the complete pipeline:
//! 1. Load rules from a directory (.rule TOML files)
//! 2. Build initial facts
//! 3. Execute with default scorer
//! 4. Execute with custom scorer
//! 5. Print report with traces

use hermes::{BinaryInfo, Fact, HeuristicEngine, ImportInfo, ScoringModel, TaintFlow, TriggeredRuleInfo};
use std::collections::HashSet;
use tempfile::tempdir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
println!("=== Hermes Rule Engine Example ===\n");

// -- Setup: Create temporary rules directory
let dir = tempdir()?;
create_sample_rules(&dir)?;

// -- Step 1: Load rules
println!("Step 1: Loading rules from directory...");
let engine = HeuristicEngine::from_paths(dir.path().to_str().unwrap(), None)?;
println!();

// -- Step 2: Build initial facts
println!("Step 2: Building initial facts...");
let facts = build_initial_facts();
println!("  Created {} initial facts", facts.len());
println!();

// -- Step 3: Execute with default scorer
println!("Step 3: Executing with default SimpleSumClampScorer...");
let report1 = engine.execute(facts.clone());
print_report(&report1, "Default Scorer");

// -- Step 4: Execute with custom scorer
println!("\nStep 4: Executing with custom MaxScorer...");
let max_scorer = MaxScorer;
let report2 = engine.execute_with_scorer(facts.clone(), &max_scorer);
print_report(&report2, "Custom MaxScorer");

// -- Step 5: Execute with weighted scorer
println!("\nStep 5: Executing with WeightedAverageScorer...");
let weighted_scorer = WeightedAverageScorer;
let report3 = engine.execute_with_scorer(facts.clone(), &weighted_scorer);
print_report(&report3, "Weighted Average Scorer");

println!("\n=== Example Complete ===");
Ok(())
}

/// Create sample rule files in the temporary directory (TOML format)
fn create_sample_rules(dir: &tempfile::TempDir) -> Result<(), Box<dyn std::error::Error>> {
// Rule 1: Detect dangerous taint flows (inline condition)
std::fs::write(
dir.path().join("rule1-taint.rule"),
r#"[[rule]]
id = "dangerous-taint-flow"
description = "Dangerous taint flow from network to unsafe sink"
condition = "TaintFlow.sink == \"strcpy\""
score = 75
justification = "strcpy is unsafe with untrusted input"
"#,
)?;

// Rule 2: Detect ELF binaries (inline condition)
std::fs::write(
dir.path().join("rule2-binary.rule"),
r#"[[rule]]
id = "elf-binary-detected"
description = "ELF binary format detected"
condition = "binary.format == \"ELF\""
score = 10
justification = "ELF is the standard Linux binary format"
"#,
)?;

// Rule 3: Detect dangerous imports (external condition file)
// First create the conditions directory
let conditions_dir = dir.path().join("conditions");
std::fs::create_dir(&conditions_dir)?;

// Create external HEL file
std::fs::write(
conditions_dir.join("dangerous-import.hel"),
r#"import.symbol CONTAINS "system""#,
)?;

// Create rule file referencing external condition
std::fs::write(
dir.path().join("rule3-imports.rule"),
r#"[[rule]]
id = "dangerous-import-detected"
description = "Dangerous function import detected"
condition_file = "conditions/dangerous-import.hel"
score = 85
justification = "system() allows arbitrary command execution"
"#,
)?;

Ok(())
}

/// Build a set of initial facts for testing
fn build_initial_facts() -> HashSet<Fact> {
let mut facts = HashSet::new();

// Add binary metadata
facts.insert(Fact::BinaryInfo(BinaryInfo {
format: "ELF".into(),
arch: "x86_64".into(),
entry_point: 0x401000,
file_size: 8192,
}));

// Add taint flow
facts.insert(Fact::TaintFlow(TaintFlow {
source: "network_recv".into(),
sink: "strcpy".into(),
}));

// Add dangerous import
facts.insert(Fact::ImportInfo(ImportInfo {
symbol: "system".into(),
library: Some("libc.so.6".into()),
}));

facts
}

/// Print a formatted report
fn print_report(report: &hermes::HeuristicReport, scorer_name: &str) {
println!("--- Report ({}) ---", scorer_name);
println!("  Final Score: {}", report.final_score);
println!("  Confidence: {:?}", report.confidence_level);
println!("  Triggered Rules: {}", report.triggered_rules.len());

for rule in &report.triggered_rules {
println!("    - {} (score: {}): {}", rule.rule_id, rule.score, rule.description);
}

println!("\n  Evaluation Traces:");
for trace in &report.evaluation_traces {
let status = match &trace.result {
hermes::RuleEvaluationResult::Triggered { score } => format!("TRIGGERED (score: {})", score),
hermes::RuleEvaluationResult::NotTriggered => "NOT TRIGGERED".to_string(),
hermes::RuleEvaluationResult::Error { message } => format!("ERROR: {}", message),
};
println!("    - {}: {}", trace.rule_id, status);
}

if let Some(ref onnx_output) = report.onnx_model_evaluation {
println!("\n  ONNX Model: {}", onnx_output);
}
}

// region:    --- Custom Scorers

/// Custom scorer that takes the maximum of all triggered rule scores
struct MaxScorer;

impl ScoringModel for MaxScorer {
fn score(&self, triggered: &[TriggeredRuleInfo]) -> u32 {
triggered.iter().map(|r| r.score).max().unwrap_or(0)
}
}

/// Custom scorer that computes weighted average
struct WeightedAverageScorer;

impl ScoringModel for WeightedAverageScorer {
fn score(&self, triggered: &[TriggeredRuleInfo]) -> u32 {
if triggered.is_empty() {
return 0;
}

// Weight higher scores more heavily
let weighted_sum: f64 = triggered.iter().map(|r| (r.score as f64).powi(2)).sum();
let weight_sum: f64 = triggered.iter().map(|r| r.score as f64).sum();

if weight_sum > 0.0 {
(weighted_sum / weight_sum).min(100.0) as u32
} else {
0
}
}
}

// endregion: --- Custom Scorers
