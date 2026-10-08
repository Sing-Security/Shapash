//! Shapash - a deterministic, auditable forward-chaining rule engine.
//!
//! Shapash owns the rules; [HEL](hel) evaluates their conditions. A rule is a TOML record with
//! an id, a score and a HEL condition; the engine fires the ones whose condition holds and
//! reports what it did.
//!
//! ```
//! use shapash::{Fact, HeuristicEngine, TaintFlow};
//! use std::collections::HashSet;
//!
//! let dir = tempfile::tempdir()?;
//! std::fs::write(dir.path().join("taint.rule"), r#"
//! [[rule]]
//! id = "dangerous-taint"
//! description = "Dangerous taint flow"
//! condition = "TaintFlow.sink == \"strcpy\""
//! score = 75
//! justification = "strcpy is unsafe with untrusted input"
//! "#)?;
//!
//! let engine = HeuristicEngine::from_paths(&dir.path().to_string_lossy(), None)?;
//!
//! let mut facts = HashSet::new();
//! facts.insert(Fact::TaintFlow(TaintFlow { source: "network".into(), sink: "strcpy".into() }));
//!
//! let report = engine.execute(facts);
//! assert_eq!(report.final_score, 75);
//! assert_eq!(report.confidence_level, shapash::ConfidenceLevel::High);
//! # Ok::<(), shapash::Error>(())
//! ```
//!
//! # Rule files
//!
//! Rules are TOML files with a `.rule` extension, read from one directory. Each `[[rule]]`
//! table needs a `condition` (an inline HEL expression) or a `condition_file` (a path
//! relative to the rules directory):
//!
//! ```toml
//! [[rule]]
//! id = "dangerous-taint-flow"
//! description = "Dangerous taint flow from network to unsafe sink"
//! condition = "TaintFlow.sink == \"strcpy\""   # inline HEL expression
//! score = 75
//! justification = "strcpy is unsafe with untrusted input"
//!
//! [[rule]]
//! id = "complex-check"
//! description = "Complex security check"
//! condition_file = "conditions/nx-check.hel"   # a HEL file, read relative to the rules dir
//! score = 85
//! justification = "NX bit should be enabled"
//! ```
//!
//! The condition in a `condition_file` is a single HEL expression, not a script: the `let`
//! bindings a `.hel` script may carry are not part of an expression and will be rejected.
//!
//! # Evaluation
//!
//! [`HeuristicEngine::execute`] runs the rules to a fixpoint. Each round evaluates every rule
//! that has not yet fired, against the fact set as it stands - including the facts earlier
//! rules added, which is what makes the chaining forward. A rule that fires contributes
//! [`Fact::TriggeredRule`] and is never evaluated again.
//!
//! A condition that fails to evaluate does not stop the run. It is recorded against that rule
//! in [`HeuristicReport::evaluation_traces`] as [`RuleEvaluationResult::Error`], and the run
//! continues.
//!
//! # Determinism
//!
//! Rules are evaluated in load order, the triggered set and the traces are sorted by rule id
//! before the report is returned, and the fact set is only ever queried, so the same rules and
//! facts give the same report. The one caveat is two facts providing the *same* attribute:
//! which one a condition sees is then up to `HashSet` iteration order. Supply one fact per
//! attribute - see [`FactSetResolver`](FactSetResolver#method.resolve_attr).
//!
//! # Cargo features
//!
//! - `onnx` (off by default) - pulls in `tract-onnx` and enables loading an ONNX model
//!   alongside the rules. Without it, the model path passed to
//!   [`HeuristicEngine::from_paths`] is accepted and ignored, and
//!   [`HeuristicReport::onnx_model_evaluation`] stays `None`.

// region:    --- Modules

mod error;
mod facts;
mod resolver;

pub use error::{Error, Result};
pub use facts::*;
pub use resolver::FactSetResolver;

// Re-export the HEL types a rule author needs to name.
pub use hel::{HelResolver, Value};

use hel::evaluate_with_resolver;
use serde::Deserialize;
use std::{collections::HashSet, path::Path, sync::Arc};

#[cfg(feature = "onnx")]
use tract_onnx::prelude::{
    Framework, Graph, InferenceModelExt, SimplePlan, Tensor, TypedFact, TypedOp,
    tract_ndarray::Array2, tvec,
};

// endregion: --- Modules

// region:    --- Rule File Format (TOML)

/// A `.rule` file: one or more `[[rule]]` tables.
#[derive(Debug, Deserialize)]
struct RuleFile {
    rule: Vec<RuleDefinition>,
}

/// One `[[rule]]` table, as it appears on disk.
///
/// Kept separate from [`HeuristicRule`] because the two differ: a definition may name a
/// condition *file*, which has to be read and checked before there is a rule.
#[derive(Debug, Deserialize)]
pub(crate) struct RuleDefinition {
    /// The rule's id, unique within the engine.
    pub(crate) id: String,
    /// What the rule means, for the report and the audit trail.
    pub(crate) description: String,
    /// The condition, inline. Mutually exclusive with `condition_file`.
    #[serde(default)]
    pub(crate) condition: Option<String>,
    /// The condition, as a path relative to the rules directory. Mutually exclusive with
    /// `condition`.
    #[serde(default)]
    pub(crate) condition_file: Option<String>,
    /// The score this rule contributes when it fires.
    pub(crate) score: u32,
    /// Why the rule is worth the score, recorded in the report.
    pub(crate) justification: String,
}

// endregion: --- Rule File Format (TOML)

// region:    --- Public Structs

/// A loaded rule.
#[derive(Debug, Clone)]
pub struct HeuristicRule {
    /// The rule's id, unique within the engine and used to keep it from firing twice.
    pub id: Arc<str>,
    /// What the rule means, in prose.
    pub description: Arc<str>,
    /// The HEL expression that has to hold for the rule to fire.
    pub condition: Arc<str>,
    /// The score the rule contributes when it fires.
    pub score: u32,
    /// Why the rule is worth the score.
    pub justification: Arc<str>,
}

/// The outcome of one [`HeuristicEngine::execute`] run.
#[derive(Debug)]
pub struct HeuristicReport {
    /// The score the scoring model produced from the rules that fired.
    pub final_score: u32,
    /// The rules that fired, sorted by id.
    pub triggered_rules: Vec<TriggeredRuleInfo>,
    /// What the ONNX model made of the facts, when one ran.
    ///
    /// `None` when no model was evaluated - the `onnx` feature is off, or no model was
    /// supplied. A model that loaded but failed is reported here as a message.
    pub onnx_model_evaluation: Option<Arc<str>>,
    /// Which band [`final_score`](Self::final_score) falls in.
    pub confidence_level: ConfidenceLevel,
    /// One entry per rule evaluated, sorted by rule id.
    pub evaluation_traces: Vec<RuleEvaluationTrace>,
}

/// A rule that fired, with the fields needed to explain why.
#[derive(Debug, Clone)]
pub struct TriggeredRuleInfo {
    /// The id of the rule that fired.
    pub rule_id: Arc<str>,
    /// That rule's description.
    pub description: Arc<str>,
    /// That rule's score.
    pub score: u32,
    /// That rule's justification.
    pub justification: Arc<str>,
}

/// What happened when one rule was evaluated.
#[derive(Debug, Clone)]
pub struct RuleEvaluationTrace {
    /// The id of the rule.
    pub rule_id: Arc<str>,
    /// The condition that was evaluated.
    pub condition: Arc<str>,
    /// The outcome.
    pub result: RuleEvaluationResult,
}

/// The outcome of evaluating a single rule.
#[derive(Debug, Clone)]
pub enum RuleEvaluationResult {
    /// The condition held, so the rule fired.
    Triggered {
        /// The score the rule contributed.
        score: u32,
    },
    /// The condition did not hold.
    NotTriggered,
    /// The condition could not be evaluated - a type error, or a call with no registry to
    /// serve it. Distinct from `NotTriggered`: the rule did not *fail* to fire, it was never
    /// successfully asked.
    Error {
        /// The evaluation error, as HEL reported it.
        message: String,
    },
}

/// A band for [`HeuristicReport::final_score`].
///
/// The boundaries live in the engine, not in the enum: 0-30 is [`Low`](ConfidenceLevel::Low),
/// 31-70 [`Medium`](ConfidenceLevel::Medium), and anything above [`High`](ConfidenceLevel::High).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidenceLevel {
    /// A score of 0-30.
    Low,
    /// A score of 31-70.
    Medium,
    /// A score of 71 or more.
    High,
}

/// The band `score` falls in - 30 and below low, 70 and below medium, above that high.
fn confidence(score: u32) -> ConfidenceLevel {
    match score {
        0..=30 => ConfidenceLevel::Low,
        31..=70 => ConfidenceLevel::Medium,
        _ => ConfidenceLevel::High,
    }
}

// endregion: --- Public Structs

// region:    --- ScoringModel Trait

/// How triggered rules become one number: sum, maximum, weighted average, anything.
pub trait ScoringModel {
    /// Reduce the rules that fired to a final score.
    fn score(&self, triggered: &[TriggeredRuleInfo]) -> u32;
}

/// The default scorer: add the triggered rules' scores, capped at [`max_score`](Self::max_score).
#[derive(Debug, Clone)]
pub struct SimpleSumClampScorer {
    /// The ceiling a sum is clamped to.
    pub max_score: u32,
}

impl SimpleSumClampScorer {
    /// A scorer that clamps at 100.
    #[must_use]
    pub fn new() -> Self {
        Self { max_score: 100 }
    }

    /// A scorer that clamps at `max_score`.
    #[must_use]
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
    /// The sum of the triggered scores, or `max_score` if the sum is larger.
    fn score(&self, triggered: &[TriggeredRuleInfo]) -> u32 {
        let sum: u32 = triggered.iter().map(|r| r.score).sum();
        sum.min(self.max_score)
    }
}

// endregion: --- ScoringModel Trait

// region:    --- Heuristic Engine

#[cfg(feature = "onnx")]
type OnnxModel = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

/// The rules, plus the optional ONNX model that reads the final fact set.
///
/// Holds no fact state: [`execute`](Self::execute) takes the facts and returns a report, and
/// nothing accumulates on the engine between runs.
pub struct HeuristicEngine {
    #[cfg(feature = "onnx")]
    model: Option<OnnxModel>,
    rules: Vec<HeuristicRule>,
}

impl HeuristicEngine {
    /// Load every `.rule` file in `rules_path`, resolving each condition from inline text or
    /// from a file next to the rules.
    ///
    /// Files are read in the order the directory listing yields them, and rules keep that order
    /// - the report is sorted afterwards, but two rules with the same id fight over which fires
    /// first. Files whose extension is not `.rule` are skipped.
    ///
    /// `model_path` is only used when the `onnx` feature is enabled; without it the argument is
    /// accepted and ignored.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if the directory cannot be read or a file cannot be opened;
    /// - [`Error::TomlParse`] if a `.rule` file is not valid TOML;
    /// - [`Error::RuleFileNotFound`] if a `condition_file` cannot be read;
    /// - [`Error::InvalidRuleDefinition`] if a rule sets both `condition` and `condition_file`;
    /// - [`Error::MissingCondition`] if it sets neither;
    /// - [`Error::RuleParseError`] if a condition is not a valid HEL expression;
    /// - `Error::OnnxModelLoadFailed` if the model cannot be loaded (only with the `onnx`
    ///   feature; the variant does not exist without it, so this is not a link).
    ///
    /// The first failure aborts loading, so a partially-loaded engine is never returned. On
    /// success every rule's condition has already been parsed, so a rule that will not parse is
    /// caught here rather than at evaluation time.
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

        #[cfg(feature = "onnx")]
        let model = if let Some(path) = model_path {
            let loaded_model = tract_onnx::onnx()
                .model_for_path(path)
                .map_err(|e| Error::OnnxModelLoadFailed(e.to_string()))?
                .into_optimized()
                .map_err(|e| Error::OnnxModelLoadFailed(e.to_string()))?
                .into_runnable()
                .map_err(|e| Error::OnnxModelLoadFailed(e.to_string()))?;
            Some(loaded_model)
        } else {
            None
        };

        // Without the feature there is no model to load; the path is taken and ignored.
        #[cfg(not(feature = "onnx"))]
        let _ = model_path;

        Ok(Self {
            rules,
            #[cfg(feature = "onnx")]
            model,
        })
    }

    /// Parse one `.rule` file into its rules.
    fn parse_rule_file(content: &str, rules_dir: &Path) -> Result<Vec<HeuristicRule>> {
        let rule_file: RuleFile = toml::from_str(content)?;
        let mut rules = Vec::new();

        for def in rule_file.rule {
            let rule = Self::load_rule(&def, rules_dir)?;
            rules.push(rule);
        }

        Ok(rules)
    }

    /// Turn one `[[rule]]` table into a rule, reading its condition file if it names one.
    ///
    /// # Errors
    ///
    /// As [`from_paths`](Self::from_paths): a definition with both or neither condition field,
    /// an unreadable condition file, or a condition that is not a valid HEL expression.
    pub(crate) fn load_rule(def: &RuleDefinition, rules_dir: &Path) -> Result<HeuristicRule> {
        let condition = match (&def.condition, &def.condition_file) {
            (Some(inline), None) => inline.clone(),
            (None, Some(path)) => {
                let full_path = rules_dir.join(path);
                std::fs::read_to_string(&full_path).map_err(|e| {
                    Error::RuleFileNotFound(format!(
                        "Failed to read condition file '{}': {}",
                        path, e
                    ))
                })?
            }
            (Some(_), Some(_)) => {
                return Err(Error::InvalidRuleDefinition(format!(
                    "Rule '{}' cannot have both 'condition' and 'condition_file'",
                    def.id
                )));
            }
            (None, None) => {
                return Err(Error::MissingCondition(format!(
                    "Rule '{}' must have either 'condition' or 'condition_file'",
                    def.id
                )));
            }
        };

        // Parse at load time so a broken rule is a loading error, not a surprise mid-run.
        // `parse_expression`, not hel's `parse_rule`, which panics on bad input.
        hel::parse_expression(&condition)
            .map_err(|e| Error::RuleParseError(format!("Rule '{}': {}", def.id, e)))?;

        Ok(HeuristicRule {
            id: def.id.clone().into(),
            description: def.description.clone().into(),
            condition: condition.into(),
            score: def.score,
            justification: def.justification.clone().into(),
        })
    }

    /// Execute the rules against `initial_facts`, scoring with [`SimpleSumClampScorer`].
    #[must_use]
    pub fn execute(&self, initial_facts: HashSet<Fact>) -> HeuristicReport {
        let scorer = SimpleSumClampScorer::new();
        self.execute_with_scorer(initial_facts, &scorer)
    }

    /// Execute the rules against `initial_facts`, scoring with `scorer`.
    ///
    /// Runs to a fixpoint: rounds repeat until one adds no new
    /// [`Fact::TriggeredRule`]. Rules are always evaluated in load order and the report is
    /// sorted, so the result does not depend on iteration order - see the
    /// [determinism note](crate#determinism).
    #[must_use]
    pub fn execute_with_scorer(
        &self,
        initial_facts: HashSet<Fact>,
        scorer: &dyn ScoringModel,
    ) -> HeuristicReport {
        let mut triggered_rules_info = Vec::new();
        let mut evaluation_traces = Vec::new();
        let mut facts = initial_facts;

        // Forward chaining: repeat while a round fires a rule that had not fired yet.
        let mut new_facts_found = true;
        while new_facts_found {
            new_facts_found = false;

            for rule in &self.rules {
                // Each rule fires once per run.
                if facts
                    .iter()
                    .any(|fact| matches!(fact, Fact::TriggeredRule(id) if id == &rule.id))
                {
                    continue;
                }

                let resolver = FactSetResolver::new(&facts);

                // A failing condition is the rule's outcome, not the run's: recorded in the
                // trace, and the engine moves on.
                match evaluate_with_resolver(&rule.condition, &resolver) {
                    Ok(true) => {
                        facts.insert(Fact::TriggeredRule(rule.id.clone()));
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

        // Sorted so the report does not depend on the order rules happened to fire in.
        triggered_rules_info.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
        evaluation_traces.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

        let final_score = scorer.score(&triggered_rules_info);

        // A model that loaded but failed is reported here as a message.
        #[cfg(feature = "onnx")]
        let onnx_model_evaluation =
            self.model
                .as_ref()
                .map(|model| match self.run_onnx_inference(model, &facts) {
                    Ok(output) => output,
                    Err(e) => format!("ONNX inference error: {}", e),
                });

        #[cfg(not(feature = "onnx"))]
        let onnx_model_evaluation: Option<String> = None;

        HeuristicReport {
            final_score,
            triggered_rules: triggered_rules_info,
            onnx_model_evaluation: onnx_model_evaluation.map(|s| s.into()),
            confidence_level: confidence(final_score),
            evaluation_traces,
        }
    }

    /// Run the model over the fact set and describe what it said.
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

        // A classifier's second output is the positive-class score; a single output is the score.
        let score = if output_slice.len() >= 2 {
            output_slice[1]
        } else if output_slice.len() == 1 {
            output_slice[0]
        } else {
            return Err(Error::OnnxInferenceFailed(
                "Unexpected output shape".to_string(),
            ));
        };

        let threshold = 0.5;
        let classification = if score > threshold {
            "positive"
        } else {
            "negative"
        };

        Ok(format!(
            "ONNX Model Output: score={:.4}, threshold={:.2}, classification={}, features_used={}",
            score, threshold, classification, features_len
        ))
    }

    /// Turn the fact set into the fixed-width feature vector the model expects.
    ///
    /// Five counts and flags are derived from the facts and the rest of the row is zero-filled,
    /// so the vector is always at least 10 wide regardless of what the model declares.
    #[cfg(feature = "onnx")]
    fn extract_features_from_facts(&self, facts: &HashSet<Fact>) -> Vec<f32> {
        let mut features = Vec::new();

        let triggered_count = facts
            .iter()
            .filter(|f| matches!(f, Fact::TriggeredRule(_)))
            .count();
        features.push(triggered_count as f32);

        let has_dangerous_imports = facts
            .iter()
            .any(|f| matches!(f, Fact::ImportInfo(info) if info.symbol.contains("system") || info.symbol.contains("exec")));
        features.push(if has_dangerous_imports { 1.0 } else { 0.0 });

        let security_flags_count = facts
            .iter()
            .filter(|f| matches!(f, Fact::SecurityFlags(_)))
            .count();
        features.push(security_flags_count as f32);

        let has_taint_flow = facts.iter().any(|f| matches!(f, Fact::TaintFlow(_)));
        features.push(if has_taint_flow { 1.0 } else { 0.0 });

        let function_call_count = facts
            .iter()
            .filter(|f| matches!(f, Fact::FunctionCall(_)))
            .count();
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
    fn test_shapash_simple_evaluation() -> Result<()> {
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
    fn test_shapash_numeric_custom_fact_compares() -> Result<()> {
        let mut facts = HashSet::new();
        facts.insert(Fact::Custom {
            namespace: "asm".into(),
            key: "gadgets".into(),
            value: "250".into(),
        });

        // A numeric custom value resolves as a Number, which is what lets the ordering
        // operators below apply at all.
        let resolver = FactSetResolver::new(&facts);
        assert!(
            evaluate_with_resolver("asm.gadgets > 200", &resolver)?,
            "250 should be > 200"
        );
        assert!(
            !evaluate_with_resolver("asm.gadgets > 300", &resolver)?,
            "250 should not be > 300"
        );
        assert!(
            evaluate_with_resolver("asm.gadgets == 250", &resolver)?,
            "250 should equal 250"
        );
        Ok(())
    }

    #[test]
    fn test_shapash_non_numeric_custom_fact_stays_a_string() -> Result<()> {
        let mut facts = HashSet::new();
        facts.insert(Fact::Custom {
            namespace: "asm".into(),
            key: "packer".into(),
            value: "present".into(),
        });

        // The numeric case must not capture a non-numeric value.
        let resolver = FactSetResolver::new(&facts);
        assert!(
            evaluate_with_resolver(r#"asm.packer == "present""#, &resolver)?,
            "string equality must still hold"
        );
        Ok(())
    }

    #[test]
    fn test_shapash_scoring_simple_sum() -> Result<()> {
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
    fn test_shapash_toml_rule_loading_inline() -> Result<()> {
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
    fn test_shapash_toml_rule_loading_external() -> Result<()> {
        let dir = tempdir()?;
        let conditions_dir = dir.path().join("conditions");
        std::fs::create_dir(&conditions_dir)?;

        std::fs::write(
            conditions_dir.join("binary-check.hel"),
            r#"binary.format == "ELF""#,
        )?;

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
    fn test_shapash_validation_both_conditions() -> Result<()> {
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
    fn test_shapash_validation_no_condition() -> Result<()> {
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
    fn test_shapash_error_custom_variant() -> Result<()> {
        // -- Setup & Fixtures
        let err = Error::custom("test error message");

        // -- Check
        assert!(matches!(err, Error::Custom(_)));
        assert_eq!(err.to_string(), "test error message");

        Ok(())
    }

    #[test]
    fn test_shapash_load_rule_missing_condition() -> Result<()> {
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
    fn test_shapash_load_rule_both_conditions() -> Result<()> {
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
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidRuleDefinition(_)
        ));

        Ok(())
    }

    #[test]
    fn test_shapash_load_rule_bad_condition_is_an_error_not_a_panic() -> Result<()> {
        // -- Setup & Fixtures
        let def = RuleDefinition {
            id: "test-rule".to_string(),
            description: "Test".to_string(),
            condition: Some("this is (not a valid HEL expression".to_string()),
            condition_file: None,
            score: 50,
            justification: "Test".to_string(),
        };

        // -- Exec
        let result = HeuristicEngine::load_rule(&def, Path::new("."));

        // -- Check
        assert!(matches!(result.unwrap_err(), Error::RuleParseError(_)));

        Ok(())
    }

    #[test]
    fn test_shapash_load_rule_rejects_a_let_script() -> Result<()> {
        // -- Setup & Fixtures: `let` belongs to a HEL script, not to a rule condition.
        let def = RuleDefinition {
            id: "test-rule".to_string(),
            description: "Test".to_string(),
            condition: Some("let x = 1\nx == 1".to_string()),
            condition_file: None,
            score: 50,
            justification: "Test".to_string(),
        };

        // -- Exec
        let result = HeuristicEngine::load_rule(&def, Path::new("."));

        // -- Check
        assert!(matches!(result.unwrap_err(), Error::RuleParseError(_)));

        Ok(())
    }
}

// endregion: --- Tests
