# Changelog

All notable changes to Shapash will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-07

### Changed
- **Custom facts with numeric values now resolve as numbers.** `FactSetResolver` returns a
  `Value::Number` for a `Fact::Custom` whose value parses as a number, so a rule can apply
  ordering operators to it (`asm.gadgets > 200`). Previously every custom value resolved as a
  string, which made any comparison other than `==` fail against it.
- **Dependency:** `hel` requirement raised from `0.2` to `0.3`. HEL 0.3 adds the default-on
  `arena` feature; it is additive and removes nothing Shapash uses.

### Compatibility
- This is a **behaviour change**, not a pure addition: a rule that compared a numeric-looking
  custom fact against its *string* form (e.g. `asm.gadgets == "250"`) now compares against a
  number and will no longer match. Rules comparing non-numeric custom facts (`== "present"`)
  are unaffected, since a non-numeric value still resolves as a string. Hence the minor bump.

### Fixed
- **LICENSE replaced with the canonical Apache-2.0 text.** The copy shipped through 0.1.15 had
  §9 mis-titled ("Additional Support" for "Additional Liability") and the APPENDIX section removed,
  while `Cargo.toml` declared `license = "Apache-2.0"`. A slightly altered licence is not that
  licence; 0.2.0 ships the verbatim text with the copyright notice filled in. (0.1.15 cannot be
  corrected after the fact — a published version can be yanked, never edited.)

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
