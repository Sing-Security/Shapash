//! Hermes — A deterministic, auditable forward-chaining rule engine
//!
//! Hermes orchestrates rules; HEL (external crate) evaluates expressions.
//!
//! ## Rule File Format
//!
//! Rules are defined in TOML `.rule` files with the following structure:
//!
//! ```toml
//! [[rule]]
//! id = "dangerous-taint-flow"
//! description = "Dangerous taint flow from network to unsafe sink"
//! condition = "TaintFlow.sink == \"strcpy\""  # Inline HEL expression
//! score = 75
//! justification = "strcpy is unsafe with untrusted input"
//!
//! [[rule]]
//! id = "complex-check"
//! description = "Complex security check"
//! condition_file = "conditions/nx-check.hel"  # External HEL file
//! score = 85
//! justification = "NX bit should be enabled"
//! ```

// region:    --- Modules

mod error;
mod facts;
mod resolver;

pub use error::{Error, Result};
pub use facts::*;
pub use resolver::FactSetResolver;

// Re-export key HEL types for convenience
pub use hel::{HelResolver, Value};

use hel::evaluate_with_resolver;
use serde::Deserialize;
use std::{collections::HashSet, path::Path, sync::Arc};

#[cfg(feature = "onnx")]
use tract_onnx::prelude::{
tract_ndarray::Array2, tvec, Framework, Graph, InferenceModelExt, SimplePlan, Tensor, TypedFact, TypedOp,
};

// endregion: --- Modules

// region:    --- Rule File Format (TOML)

/// Rule file structure (TOML format)
#[derive(Debug, Deserialize)]
struct RuleFile {
rule: Vec<RuleDefinition>,
}

/// Individual rule definition from TOML
#[derive(Debug, Deserialize)]
pub(crate) struct RuleDefinition {
pub(crate) id: String,
pub(crate) description: String,
#[serde(default)]
pub(crate) condition: Option<String>,
#[serde(default)]
pub(crate) condition_file: Option<String>,
pub(crate) score: u32,
pub(crate) justification: String,
}

// endregion: --- Rule File Format (TOML)

// region:    --- Public Structs

/// A heuristic rule with metadata and condition expression
#[derive(Debug, Clone)]
pub struct HeuristicRule {
pub id: Arc<str>,
pub description: Arc<str>,
/// HEL condition expression (evaluated by external hel crate)
pub condition: Arc<str>,
pub score: u32,
pub justification: Arc<str>,
}

/// Report generated after rule evaluation
#[derive(Debug)]
pub struct HeuristicReport {
pub final_score: u32,
pub triggered_rules: Vec<TriggeredRuleInfo>,
pub onnx_model_evaluation: Option<Arc<str>>,
pub confidence_level: ConfidenceLevel,
/// Per-rule evaluation results with traces (deterministically ordered)
pub evaluation_traces: Vec<RuleEvaluationTrace>,
}

/// Information about a triggered rule
#[derive(Debug, Clone)]
pub struct TriggeredRuleInfo {
pub rule_id: Arc<str>,
pub description: Arc<str>,
pub score: u32,
pub justification: Arc<str>,
}

/// Trace of a single rule evaluation
#[derive(Debug, Clone)]
pub struct RuleEvaluationTrace {
pub rule_id: Arc<str>,
pub condition: Arc<str>,
pub result: RuleEvaluationResult,
}

/// Result of evaluating a single rule
#[derive(Debug, Clone)]
pub enum RuleEvaluationResult {
/// Rule triggered successfully
Triggered { score: u32 },
/// Rule did not trigger
NotTriggered,
/// Rule evaluation failed
Error { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidenceLevel {
Low,
Medium,
High,
}

fn confidence(score: u32) -> ConfidenceLevel {
match score {
0..=30 => ConfidenceLevel::Low,
31..=70 => ConfidenceLevel::Medium,
_ => ConfidenceLevel::High,
}
}

// endregion: --- Public Structs

// region:    --- ScoringModel Trait

/// Pluggable scoring model trait
pub trait ScoringModel {
/// Calculate final score from triggered rules
fn score(&self, triggered: &[TriggeredRuleInfo]) -> u32;
}

/// Simple sum-and-clamp scorer (default OSS implementation)
#[derive(Debug, Clone)]
pub struct SimpleSumClampScorer {
pub max_score: u32,
}

impl SimpleSumClampScorer {
pub fn new() -> Self {
Self { max_score: 100 }
}

pub fn with_max(max_score: u32) -> Self {
Self { max_score }
}
}

impl Default for SimpleSumClampScorer {
fn default() -> Self {
Self::new()
}
}

impl ScoringModel for SimpleSumClampScorer {
fn score(&self, triggered: &[TriggeredRuleInfo]) -> u32 {
let sum: u32 = triggered.iter().map(|r| r.score).sum();
sum.min(self.max_score)
}
}

// endregion: --- ScoringModel Trait

// region:    --- Heuristic Engine

#[cfg(feature = "onnx")]
type OnnxModel = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

/// Forward-chaining rule engine with pluggable scoring
pub struct HeuristicEngine {
#[cfg(feature = "onnx")]
model: Option<OnnxModel>,
rules: Vec<HeuristicRule>,
}

impl HeuristicEngine {
/// Load rules from a directory of .rule (TOML) files
///
/// # Arguments
/// * `rules_path` - Path to directory containing .rule TOML files
/// * `model_path` - Optional path to ONNX model file
///
/// # Rule File Format
///
/// Rules are defined in TOML `.rule` files. Each rule must have either:
/// - `condition`: Inline HEL expression
/// - `condition_file`: Path to external .hel file (relative to rules directory)
///
/// # Returns
/// Result containing the engine or an error
///
/// # Errors
/// Returns error if:
/// - Directory cannot be read
/// - Rule files cannot be parsed
/// - Rules have both `condition` and `condition_file`
/// - Rules have neither `condition` nor `condition_file`
/// - HEL syntax validation fails
/// - ONNX model cannot be loaded
pub fn from_paths(rules_path: &str, model_path: Option<&str>) -> Result<Self> {
let rules_dir = Path::new(rules_path);
let mut rules = Vec::new();

for entry in std::fs::read_dir(rules_dir)? {
let entry = entry?;
let path = entry.path();
if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("rule") {
let content = std::fs::read_to_string(&path)?;
let parsed_rules = Self::parse_rule_file(&content, rules_dir)?;
rules.extend(parsed_rules);
}
}

println!("Loaded {} rules from {}", rules.len(), rules_path);

#[cfg(feature = "onnx")]
let model = if let Some(path) = model_path {
println!("ONNX model path provided. Loading from {}", path);
let loaded_model = tract_onnx::onnx()
.model_for_path(path)
.map_err(|e| Error::OnnxModelLoadFailed(e.to_string()))?
.into_optimized()
.map_err(|e| Error::OnnxModelLoadFailed(e.to_string()))?
.into_runnable()
.map_err(|e| Error::OnnxModelLoadFailed(e.to_string()))?;
Some(loaded_model)
} else {
println!("No ONNX model path provided. Skipping model loading.");
None
};

#[cfg(not(feature = "onnx"))]
if model_path.is_some() {
println!("ONNX model path provided but onnx feature not enabled. Skipping model loading.");
}

Ok(Self {
rules,
#[cfg(feature = "onnx")]
model,
})
}

/// Parse a TOML rule file and load rule definitions
fn parse_rule_file(content: &str, rules_dir: &Path) -> Result<Vec<HeuristicRule>> {
let rule_file: RuleFile = toml::from_str(content)?;
let mut rules = Vec::new();

for def in rule_file.rule {
let rule = Self::load_rule(&def, rules_dir)?;
rules.push(rule);
}

Ok(rules)
}

/// Load a single rule definition, resolving condition from inline or external file
pub(crate) fn load_rule(def: &RuleDefinition, rules_dir: &Path) -> Result<HeuristicRule> {
// Validate: must have exactly one of condition or condition_file
let condition = match (&def.condition, &def.condition_file) {
(Some(inline), None) => inline.clone(),
(None, Some(path)) => {
let full_path = rules_dir.join(path);
std::fs::read_to_string(&full_path).map_err(|e| {
Error::RuleFileNotFound(format!("Failed to read condition file '{}': {}", path, e))
})?
}
(Some(_), Some(_)) => {
return Err(Error::InvalidRuleDefinition(format!(
"Rule '{}' cannot have both 'condition' and 'condition_file'",
def.id
)))
}
(None, None) => {
return Err(Error::MissingCondition(format!(
"Rule '{}' must have either 'condition' or 'condition_file'",
def.id
)))
}
};

// Parse HEL syntax early using external hel crate (fail fast)
		let _ast = hel::parse_rule(&condition); // Validates syntax

Ok(HeuristicRule {
id: def.id.clone().into(),
description: def.description.clone().into(),
condition: condition.into(),
score: def.score,
justification: def.justification.clone().into(),
})
}

/// Execute rules with default scoring
pub fn execute(&self, initial_facts: HashSet<Fact>) -> HeuristicReport {
let scorer = SimpleSumClampScorer::new();
self.execute_with_scorer(initial_facts, &scorer)
}

/// Execute rules with custom scoring model
pub fn execute_with_scorer(&self, initial_facts: HashSet<Fact>, scorer: &dyn ScoringModel) -> HeuristicReport {
let mut triggered_rules_info = Vec::new();
let mut evaluation_traces = Vec::new();
let mut facts = initial_facts;

// Forward chaining
let mut new_facts_found = true;
while new_facts_found {
new_facts_found = false;

for rule in &self.rules {
if facts
.iter()
.any(|fact| matches!(fact, Fact::TriggeredRule(id) if id == &rule.id))
{
continue;
}

let resolver = FactSetResolver::new(&facts);

match evaluate_with_resolver(&rule.condition, &resolver) {
Ok(true) => {
let new_fact = Fact::TriggeredRule(rule.id.clone());
facts.insert(new_fact);
new_facts_found = true;

triggered_rules_info.push(TriggeredRuleInfo {
rule_id: rule.id.clone(),
description: rule.description.clone(),
score: rule.score,
justification: rule.justification.clone(),
});

evaluation_traces.push(RuleEvaluationTrace {
rule_id: rule.id.clone(),
condition: rule.condition.clone(),
result: RuleEvaluationResult::Triggered { score: rule.score },
});
}
Ok(false) => {
evaluation_traces.push(RuleEvaluationTrace {
rule_id: rule.id.clone(),
condition: rule.condition.clone(),
result: RuleEvaluationResult::NotTriggered,
});
}
Err(e) => {
eprintln!("Error evaluating rule '{}': {}", rule.id, e);
evaluation_traces.push(RuleEvaluationTrace {
rule_id: rule.id.clone(),
condition: rule.condition.clone(),
result: RuleEvaluationResult::Error {
message: e.to_string(),
},
});
}
}
}
}

// Deterministic ordering
triggered_rules_info.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
evaluation_traces.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

let final_score = scorer.score(&triggered_rules_info);

#[cfg(feature = "onnx")]
let onnx_model_evaluation = if let Some(ref model) = self.model {
match self.run_onnx_inference(model, &facts) {
Ok(output) => Some(output),
Err(e) => {
eprintln!("ONNX inference failed: {}", e);
Some(format!("ONNX inference error: {}", e))
}
}
} else {
Some("No ONNX model was loaded".to_string())
};

#[cfg(not(feature = "onnx"))]
let onnx_model_evaluation = Some("ONNX feature not enabled".to_string());

let onnx_model_evaluation: Option<Arc<str>> = onnx_model_evaluation.map(|s| s.into());

HeuristicReport {
final_score,
triggered_rules: triggered_rules_info,
onnx_model_evaluation,
confidence_level: confidence(final_score),
evaluation_traces,
}
}

#[cfg(feature = "onnx")]
fn run_onnx_inference(&self, model: &OnnxModel, facts: &HashSet<Fact>) -> Result<String> {
let feature_vector = self.extract_features_from_facts(facts);
let features_len = feature_vector.len();
let input = Array2::from_shape_vec((1, features_len), feature_vector)
.map_err(|e| Error::OnnxInferenceFailed(e.to_string()))?;
let input_tensor = input.into_dyn();

let result = model
.run(tvec!(Tensor::from(input_tensor).into()))
.map_err(|e| Error::OnnxInferenceFailed(e.to_string()))?;
let output = result[0]
.to_array_view::<f32>()
.map_err(|e| Error::OnnxInferenceFailed(e.to_string()))?;
let output_slice = output
.as_slice()
.ok_or_else(|| Error::OnnxInferenceFailed("Failed to get output slice".to_string()))?;

let score = if output_slice.len() >= 2 {
output_slice[1]
} else if output_slice.len() == 1 {
output_slice[0]
} else {
return Err(Error::OnnxInferenceFailed("Unexpected output shape".to_string()));
};

let threshold = 0.5;
let classification = if score > threshold { "positive" } else { "negative" };

Ok(format!(
"ONNX Model Output: score={:.4}, threshold={:.2}, classification={}, features_used={}",
score, threshold, classification, features_len
))
}

#[cfg(feature = "onnx")]
fn extract_features_from_facts(&self, facts: &HashSet<Fact>) -> Vec<f32> {
let mut features = Vec::new();

let triggered_count = facts.iter().filter(|f| matches!(f, Fact::TriggeredRule(_))).count();
features.push(triggered_count as f32);

let has_dangerous_imports = facts.iter().any(
|f| matches!(f, Fact::ImportInfo(info) if info.symbol.contains("system") || info.symbol.contains("exec")),
);
features.push(if has_dangerous_imports { 1.0 } else { 0.0 });

let security_flags_count = facts.iter().filter(|f| matches!(f, Fact::SecurityFlags(_))).count();
features.push(security_flags_count as f32);

let has_taint_flow = facts.iter().any(|f| matches!(f, Fact::TaintFlow(_)));
features.push(if has_taint_flow { 1.0 } else { 0.0 });

let function_call_count = facts.iter().filter(|f| matches!(f, Fact::FunctionCall(_))).count();
features.push(function_call_count as f32);

while features.len() < 10 {
features.push(0.0);
}

features
}
}

// endregion: --- Heuristic Engine

// region:    --- Tests

#[cfg(test)]
mod tests {
type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

use super::*;
use tempfile::tempdir;

#[test]
fn test_hermes_simple_evaluation() -> Result<()> {
let mut facts = HashSet::new();
facts.insert(Fact::BinaryInfo(BinaryInfo {
format: "ELF".into(),
arch: "x86_64".into(),
entry_point: 0x1000,
file_size: 4096,
}));

let condition = r#"binary.format == "ELF""#;
let resolver = FactSetResolver::new(&facts);
let result = evaluate_with_resolver(condition, &resolver)?;

assert!(result, "Binary format should match ELF");
Ok(())
}

#[test]
fn test_hermes_scoring_simple_sum() -> Result<()> {
let scorer = SimpleSumClampScorer::new();
let triggered = vec![
TriggeredRuleInfo {
rule_id: "rule1".into(),
description: "Test rule 1".into(),
score: 30,
justification: "Test".into(),
},
TriggeredRuleInfo {
rule_id: "rule2".into(),
description: "Test rule 2".into(),
score: 40,
justification: "Test".into(),
},
];

let score = scorer.score(&triggered);
assert_eq!(score, 70, "Score should be sum of triggered rules");
Ok(())
}

#[test]
fn test_hermes_toml_rule_loading_inline() -> Result<()> {
let dir = tempdir()?;
let rule_path = dir.path().join("test.rule");

std::fs::write(
&rule_path,
r#"[[rule]]
id = "taint-detected"
description = "Taint flow from network to dangerous sink"
condition = "TaintFlow.sink == \"strcpy\""
score = 75
justification = "strcpy is dangerous with network input"
"#,
)?;

let engine = HeuristicEngine::from_paths(dir.path().to_str().unwrap(), None)?;

let mut facts = HashSet::new();
facts.insert(Fact::TaintFlow(TaintFlow {
source: "network".into(),
sink: "strcpy".into(),
}));

let report = engine.execute(facts);

assert_eq!(report.triggered_rules.len(), 1);
assert_eq!(report.triggered_rules[0].rule_id.as_ref(), "taint-detected");
assert_eq!(report.final_score, 75);
assert_eq!(report.evaluation_traces.len(), 1);

Ok(())
}

#[test]
fn test_hermes_toml_rule_loading_external() -> Result<()> {
let dir = tempdir()?;
let conditions_dir = dir.path().join("conditions");
std::fs::create_dir(&conditions_dir)?;

// Create external HEL file
std::fs::write(
conditions_dir.join("binary-check.hel"),
r#"binary.format == "ELF""#,
)?;

// Create rule file referencing external condition
std::fs::write(
dir.path().join("test.rule"),
r#"[[rule]]
id = "elf-check"
description = "ELF binary detected"
condition_file = "conditions/binary-check.hel"
score = 10
justification = "ELF is standard Linux format"
"#,
)?;

let engine = HeuristicEngine::from_paths(dir.path().to_str().unwrap(), None)?;

let mut facts = HashSet::new();
facts.insert(Fact::BinaryInfo(BinaryInfo {
format: "ELF".into(),
arch: "x86_64".into(),
entry_point: 0x1000,
file_size: 4096,
}));

let report = engine.execute(facts);

assert_eq!(report.triggered_rules.len(), 1);
assert_eq!(report.triggered_rules[0].rule_id.as_ref(), "elf-check");

Ok(())
}

#[test]
fn test_hermes_validation_both_conditions() -> Result<()> {
let dir = tempdir()?;
let rule_path = dir.path().join("test.rule");

std::fs::write(
&rule_path,
r#"[[rule]]
id = "invalid"
description = "Invalid rule"
condition = "true"
condition_file = "test.hel"
score = 50
justification = "Should fail"
"#,
)?;

let result = HeuristicEngine::from_paths(dir.path().to_str().unwrap(), None);
assert!(result.is_err(), "Should reject rule with both conditions");

Ok(())
}

#[test]
fn test_hermes_validation_no_condition() -> Result<()> {
let dir = tempdir()?;
let rule_path = dir.path().join("test.rule");

std::fs::write(
&rule_path,
r#"[[rule]]
id = "invalid"
description = "Invalid rule"
score = 50
justification = "Should fail"
"#,
)?;

let result = HeuristicEngine::from_paths(dir.path().to_str().unwrap(), None);
assert!(result.is_err(), "Should reject rule with no condition");

Ok(())
}

#[test]
fn test_hermes_error_custom_variant() -> Result<()> {
// -- Setup & Fixtures
let err = Error::custom("test error message");

// -- Check
assert!(matches!(err, Error::Custom(_)));
assert_eq!(err.to_string(), "Custom(\"test error message\")");

Ok(())
}

#[test]
fn test_hermes_load_rule_missing_condition() -> Result<()> {
// -- Setup & Fixtures
let def = RuleDefinition {
id: "test-rule".to_string(),
description: "Test".to_string(),
condition: None,
condition_file: None,
score: 50,
justification: "Test".to_string(),
};

// -- Exec
let result = HeuristicEngine::load_rule(&def, Path::new("."));

// -- Check
assert!(result.is_err());
assert!(matches!(result.unwrap_err(), Error::MissingCondition(_)));

Ok(())
}

#[test]
fn test_hermes_load_rule_both_conditions() -> Result<()> {
// -- Setup & Fixtures
let def = RuleDefinition {
id: "test-rule".to_string(),
description: "Test".to_string(),
condition: Some("test".to_string()),
condition_file: Some("test.hel".to_string()),
score: 50,
justification: "Test".to_string(),
};

// -- Exec
let result = HeuristicEngine::load_rule(&def, Path::new("."));

// -- Check
assert!(result.is_err());
assert!(matches!(result.unwrap_err(), Error::InvalidRuleDefinition(_)));

Ok(())
}
}

// endregion: --- Tests
