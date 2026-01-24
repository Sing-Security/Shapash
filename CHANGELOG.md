# Changelog

All notable changes to Shapash will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-01-23

### Added
- Initial release of Shapash rule engine
- TOML `.rule` file format with `condition` and `condition_file` support
- Integration with external HEL 0.2.0 for expression evaluation
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
