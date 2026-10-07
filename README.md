# Shapash — Deterministic Rule Engine

[![Crates.io](https://img.shields.io/crates/v/shapash.svg)](https://crates.io/crates/shapash)
[![Documentation](https://docs.rs/shapash/badge.svg)](https://docs.rs/shapash)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Shapash is a deterministic, auditable forward-chaining rule engine designed for security analysis, compliance workflows, and intelligent automation.

Shapash owns the rules; [HEL (Heuristics Expression Language)](https://crates.io/crates/hel) evaluates their conditions.

## Features

- **Deterministic Evaluation**: Rules run in load order and the report is sorted, so the same rules and facts produce the same report
- **HEL Integration**: Rule conditions are HEL expressions, inline or in a `.hel` file
- **Pluggable Scoring**: Trait-based scoring models for custom risk calculations
- **TOML Rule Format**: Clean `.rule` files with inline or external HEL conditions
- **ONNX Model Support**: Optional ML model integration for advanced scoring (the `onnx` feature)
- **Audit Trails**: Per-rule evaluation traces for compliance

## Quick Start

### Define Rules (TOML)

Create a `.rule` file:

```toml
[[rule]]
id = "high-risk-taint"
description = "Dangerous taint flow detected"
condition = 'TaintFlow.sink == "strcpy"'  # Inline HEL expression
score = 75
justification = "strcpy is unsafe with untrusted input"

[[rule]]
id = "security-check"
description = "Complex security validation"
condition_file = "conditions/nx-check.hel"  # HEL expression, read relative to the rules dir
score = 85
justification = "NX protection should be enabled"
```

### Evaluate Rules

```rust
use shapash::{Fact, HeuristicEngine, TaintFlow};
use std::collections::HashSet;

fn main() -> Result<(), shapash::Error> {
    // Load every .rule file in the directory.
    let engine = HeuristicEngine::from_paths("rules/", None)?;

    // Provide facts for evaluation.
    let mut facts = HashSet::new();
    facts.insert(Fact::TaintFlow(TaintFlow {
        source: "network".into(),
        sink: "strcpy".into(),
    }));

    // Execute the rules.
    let report = engine.execute(facts);

    println!("Final Score: {}", report.final_score);
    for rule in &report.triggered_rules {
        println!("  ✓ {}: {}", rule.rule_id, rule.description);
    }

    Ok(())
}
```

### Custom Scoring Models

Implement your own scoring logic:

```rust
use shapash::{HeuristicReport, ScoringModel, TriggeredRuleInfo};

struct MaxScorer;

impl ScoringModel for MaxScorer {
    fn score(&self, triggered: &[TriggeredRuleInfo]) -> u32 {
        triggered.iter().map(|r| r.score).max().unwrap_or(0)
    }
}

fn score_it(engine: &shapash::HeuristicEngine, facts: std::collections::HashSet<shapash::Fact>) -> HeuristicReport {
    // `execute_with_scorer` returns the report directly; it has no error channel.
    engine.execute_with_scorer(facts, &MaxScorer)
}
```

## Rule File Format

Rules support both inline and external HEL conditions:

### Inline Condition

```toml
[[rule]]
id = "example"
condition = 'binary.arch == "x86_64" AND security.nx == false'
score = 50
justification = "..."
description = "..."
```

### External Condition File

```toml
[[rule]]
id = "example"
condition_file = "conditions/android-malware.hel"
score = 90
justification = "..."
description = "..."
```

File: `conditions/android-malware.hel`

```hel
manifest.permissions CONTAINS "READ_SMS" AND binary.entropy > 7.5
```

A condition file holds one HEL **expression**, not a script. The `let` bindings a `.hel`
script may carry are not part of an expression and are rejected at load time with
`Error::RuleParseError`.

## Facts and Object Names

A rule addresses facts through fixed object names, so `binary.format` reads the `format`
attribute of a `Fact::BinaryInfo`:

| Object name | Fact variant | Attributes |
|---|---|---|
| `binary` | `Fact::BinaryInfo` | `format`, `arch`, `entry_point`, `file_size` |
| `security` | `Fact::SecurityFlags` | `<flag_name>` (the flag's own name) |
| `section` | `Fact::SectionInfo` | `name`, `is_executable`, `is_writable` |
| `import` | `Fact::ImportInfo` | `symbol`, `library` |
| `TaintFlow` | `Fact::TaintFlow` | `source`, `sink` |
| `FunctionCall` | `Fact::FunctionCall` | `name`, `arguments`, `properties` |
| `MemoryOperation` | `Fact::MemoryOperation` | `destination_address`, `is_write` |
| `OnnxModelOutput` | `Fact::OnnxModelOutput` | the text itself |
| `TriggeredRule` | `Fact::TriggeredRule` | the rule id |
| `<namespace>` | `Fact::Custom` | `<key>` |

`Fact::SymQueryRequest` and `Fact::SymQueryResult` have no object name: they can sit in the
set, but no condition can read them.

An attribute with no fact behind it resolves to a null, and a comparison against it is
false — not an error. Give one fact per attribute: if two facts provide the same attribute,
the fact set is a `HashSet` and which one a condition sees depends on its iteration order.

## Architecture

```
┌─────────────────────────────────────────────┐
│ Shapash                                     │
│ • Rule orchestration                        │
│ • Fact management                           │
│ • Scoring coordination                      │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ HEL (external crate)                        │
│ • Expression evaluation                     │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ Products                                     │
│ • Inject domain-specific facts              │
│ • Custom scoring models                     │
└─────────────────────────────────────────────┘
```

## Limitations

- A condition that fails to evaluate does not fail the run. It is recorded against that rule
  in `HeuristicReport::evaluation_traces` as `RuleEvaluationResult::Error`, and the engine
  continues.
- `u64` fact fields reach a condition as a `f64`, so they are exact only up to 2^53.
- The `onnx` feature pulls in `tract-onnx`, a large dependency tree; it is off by default.

## Example

See `examples/c01-simple-pipeline.rs` for a complete working example
(`cargo run --example c01-simple-pipeline`).

## Requirements

Rust 1.85 or later. No `unsafe`, no build script.

## License

Apache-2.0. See LICENSE for details.
