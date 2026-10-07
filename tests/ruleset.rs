//! Integration test over the ruleset checked in under `tests/fixtures/`.
//!
//! The unit tests build their rule files in a temp directory; this one loads the fixture as it
//! sits on disk. That is what covers a `condition_file` being resolved relative to the rules
//! directory rather than to the process's working directory.

use shapash::{BinaryInfo, ConfidenceLevel, Fact, HeuristicEngine, TaintFlow};
use std::collections::HashSet;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn test_fixture_ruleset_loads_and_fires() -> Result<(), Box<dyn std::error::Error>> {
    // -- Exec
    let engine = HeuristicEngine::from_paths(&fixtures_dir().to_string_lossy(), None)?;

    let mut facts = HashSet::new();
    facts.insert(Fact::BinaryInfo(BinaryInfo {
        format: "ELF".into(),
        arch: "x86_64".into(),
        entry_point: 0x1000,
        file_size: 4096,
    }));
    facts.insert(Fact::TaintFlow(TaintFlow {
        source: "network".into(),
        sink: "strcpy".into(),
    }));

    let report = engine.execute(facts);

    // -- Check: both rules fire, including the one whose condition lives in a file.
    let ids: Vec<&str> = report
        .triggered_rules
        .iter()
        .map(|r| r.rule_id.as_ref())
        .collect();
    assert_eq!(ids, ["elf-binary", "taint-flow"]);
    assert_eq!(report.final_score, 85);
    assert_eq!(report.confidence_level, ConfidenceLevel::High);
    assert_eq!(report.evaluation_traces.len(), 2);
    assert!(report.onnx_model_evaluation.is_none());

    Ok(())
}

#[test]
fn test_fixture_ruleset_against_no_matching_facts() -> Result<(), Box<dyn std::error::Error>> {
    // -- Exec: an empty fact set must leave every rule untriggered, not errored.
    let engine = HeuristicEngine::from_paths(&fixtures_dir().to_string_lossy(), None)?;
    let report = engine.execute(HashSet::new());

    // -- Check
    assert!(report.triggered_rules.is_empty());
    assert_eq!(report.final_score, 0);
    assert_eq!(report.confidence_level, ConfidenceLevel::Low);
    assert!(
        report
            .evaluation_traces
            .iter()
            .all(|t| matches!(t.result, shapash::RuleEvaluationResult::NotTriggered)),
        "an absent fact is a null the condition compares false against, not an error"
    );

    Ok(())
}
