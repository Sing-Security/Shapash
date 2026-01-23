# Hermes — Deterministic Rule Engine

[![Crates.io](https://img.shields.io/crates/v/hermes-engine.svg)](https://crates.io/crates/hermes-engine)
[![Documentation](https://docs.rs/hermes-engine/badge.svg)](https://docs.rs/hermes-engine)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Hermes is a deterministic, auditable forward-chaining rule engine designed for security analysis, compliance workflows, and intelligent automation.

## Features

- **Deterministic Evaluation**: Stable rule ordering and reproducible results
- **HEL Integration**: Uses [HEL (Heuristics Expression Language)](https://crates.io/crates/hel) for rule conditions
- **Pluggable Scoring**: Trait-based scoring models for custom risk calculations
- **TOML Rule Format**: Clean `.rule` files with inline or external HEL conditions
- **ONNX Model Support**: Optional ML model integration for advanced scoring
- **Audit Trails**: Per-rule evaluation traces for compliance

## Quick Start

### Define Rules (TOML)

Create a `.rule` file:

```toml
[[rule]]
id = "high-risk-taint"
description = "Dangerous taint flow detected"
condition = 'TaintFlow.sink == "strcpy"'  # Inline HEL
score = 75
justification = "strcpy is unsafe with untrusted input"

[[rule]]
id = "security-check"
description = "Complex security validation"
condition_file = "conditions/nx-check.hel"  # External HEL script
score = 85
justification = "NX protection should be enabled"
```

### Evaluate Rules

```rust
use hermes::{HeuristicEngine, Fact, TaintFlow};
use std::collections::HashSet;

// Load rules from .rule files
let engine = HeuristicEngine::from_paths("rules/", None)?;

// Provide facts for evaluation
let mut facts = HashSet::new();
facts.insert(Fact::TaintFlow(TaintFlow {
    source: "network".into(),
    sink: "strcpy".into(),
}));

// Execute rule engine
let report = engine.execute(facts);

println!("Final Score: {}", report.final_score);
for rule in &report.triggered_rules {
    println!("  ✓ {}: {}", rule.rule_id, rule.description);
}
```

### Custom Scoring Models

Implement your own scoring logic:

```rust
use hermes::{ScoringModel, TriggeredRuleInfo};

struct CustomScorer;

impl ScoringModel for CustomScorer {
    fn score(&self, triggered: &[TriggeredRuleInfo]) -> u32 {
        // Custom scoring algorithm
        triggered.iter().map(|r| r.score).max().unwrap_or(0)
    }
}

let report = engine.execute_with_scorer(facts, &CustomScorer)?;
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
let has_sms = manifest.permissions CONTAINS "READ_SMS"
let obfuscated = binary.entropy > 7.5

has_sms AND obfuscated
```

## Architecture

```
┌─────────────────────────────────────────────┐
│ Hermes                                      │
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

## Example

See `examples/c01-simple-pipeline.rs` for a complete working example.

## License

Apache-2.0. See LICENSE for details.
