# Changelog

All notable changes to Shapash will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-10-07

### Changed

- Prose typography normalized to ASCII: em/en dashes, curly quotes, ellipses and
  Unicode arrows in comments and docs are now plain `-`, `"`, `'`, `...` and `-->`.
  No API or behaviour change; a republish of 0.2.0 with cleaner source.

## [0.2.0] - 2026-10-07

### Changed
- **Custom facts with numeric values now resolve as numbers.** `FactSetResolver` returns a
  `Value::Number` for a `Fact::Custom` whose value parses as a number, so a rule can apply
  ordering operators to it (`asm.gadgets > 200`). Previously every custom value resolved as a
  string, which made any comparison other than `==` fail against it.
- **Dependency:** `hel` requirement raised from `0.2` to `0.3`. HEL 0.3 adds the default-on
  `arena` feature; it is additive and removes nothing Shapash uses.
- **`Error`'s `Display` now renders the message, not the variant.** `err.to_string()` returned
  the `Debug` form (`Custom("...")`, `InvalidRuleDefinition("...")`); it now returns the message
  the variant carries (`"..."`). Error strings that matched the old shape will need updating.
- **`HeuristicReport::onnx_model_evaluation` is `None` when no model ran.** It previously held a
  placeholder string (`"ONNX feature not enabled"`, `"No ONNX model was loaded"`) that a caller
  had to string-match. Without the `onnx` feature, or with no model supplied, the field is now
  `None`. A model that *loaded* but failed at inference is still reported here, as
  `"ONNX inference error: ..."`.
- **The library no longer prints.** `from_paths` printed a line per rule file it loaded and
  `execute_with_scorer` printed on a rule-evaluation failure and on an ONNX failure. A library
  writing to stdout/stderr uninvited is a surprise in a program that owns its own output; the
  evaluation failure is already carried per rule in `HeuristicReport::evaluation_traces`.

### Compatibility
- This is a **behaviour change**, not a pure addition: a rule that compared a numeric-looking
  custom fact against its *string* form (e.g. `asm.gadgets == "250"`) now compares against a
  number and will no longer match. Rules comparing non-numeric custom facts (`== "present"`)
  are unaffected, since a non-numeric value still resolves as a string. Hence the minor bump.

### Fixed
- **A bad rule condition is a load error, not a panic.** `from_paths` parsed each condition with
  a panicking entry point, so a syntactically invalid condition - or a `condition_file` holding
  `let` bindings, or trailing junk - aborted the process instead of returning the
  `Error::RuleParseError` its `# Errors` section documented. Conditions are now parsed with the
  fallible path, and the variant is reachable as documented.
- **LICENSE replaced with the canonical Apache-2.0 text.** The copy shipped through 0.1.15 had
  §9 mis-titled ("Additional Support" for "Additional Liability") and the APPENDIX section removed,
  while `Cargo.toml` declared `license = "Apache-2.0"`. A slightly altered licence is not that
  licence; 0.2.0 ships the verbatim text with the copyright notice filled in. (0.1.15 cannot be
  corrected after the fact - a published version can be yanked, never edited.)

### Known limitations
- A fact set holding two facts that provide the *same* attribute has no defined answer: the set
  is a `HashSet`, so which one a condition sees depends on iteration order. Give one fact per
  attribute. (Documented, not changed - choosing the semantics is a design decision.)
- A `condition_file` must hold a single HEL expression. The `let` bindings a HEL *script* may
  carry are not expressions and are rejected at load time.

## [0.1.15] - 2026-01-24

The last 0.1.x release. The bump commits between 0.1.0 and 0.1.15 were not individually
recorded here; the entries below describe the 0.1.0 feature set that carried forward.

## [0.1.0] - 2026-01-23

### Added
- Initial release of Shapash rule engine
- TOML `.rule` file format with `condition` and `condition_file` support
- Integration with external HEL for expression evaluation
- `ScoringModel` trait for pluggable scoring algorithms
- `SimpleSumClampScorer` default implementation
- ONNX model support for ML-based scoring
- Per-rule evaluation traces for audit
- `FactSetResolver` for HEL integration
- Forward-chaining rule evaluation
- Deterministic rule ordering and trace generation

### Changed
- Removed internal HEL parser (now uses external `hel` crate from Sing-Security)
- Extracted proprietary scoring to separate crate (clean OSS boundary)

### Fixed
- Deterministic rule ordering
- Stable trace generation with sorted output

[0.2.0]: https://github.com/Sing-Security/Shapash/compare/v0.1.15...v0.2.0
[0.1.15]: https://github.com/Sing-Security/Shapash/releases/tag/v0.1.15
[0.1.0]: https://github.com/Sing-Security/Shapash/releases/tag/v0.1.0
