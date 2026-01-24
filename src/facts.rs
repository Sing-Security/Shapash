//! Domain-specific fact types for Shapash rule evaluation
//!
//! These types represent facts that can be evaluated by HEL expressions.

use std::sync::Arc;

/// A fact in the rule evaluation system
///
/// Facts represent information about binaries, behaviors, and analysis results.
/// They can be referenced in HEL rule conditions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Fact {
/// Rule that has been triggered (for forward chaining)
TriggeredRule(Arc<str>),
/// Taint flow analysis result
TaintFlow(TaintFlow),
/// Function call observation
FunctionCall(FunctionCall),
/// Memory operation observation
MemoryOperation(MemoryOperation),
/// ONNX model output
OnnxModelOutput(Arc<str>),
/// Binary metadata
BinaryInfo(BinaryInfo),
/// Security flag status
SecurityFlags(SecurityFlags),
/// Binary section information
SectionInfo(SectionInfo),
/// Import/symbol information
ImportInfo(ImportInfo),
/// Symbolic execution query request
SymQueryRequest(SymQueryRequest),
/// Symbolic execution query result
SymQueryResult(SymQueryResult),
/// Custom fact with namespace, key, and value
Custom {
namespace: Arc<str>,
key: Arc<str>,
value: Arc<str>,
},
}

/// Taint flow analysis result
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaintFlow {
pub source: Arc<str>,
pub sink: Arc<str>,
}

/// Function call observation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionCall {
pub name: Arc<str>,
pub arguments: Vec<Arc<str>>,
pub properties: Vec<Arc<str>>,
}

/// Memory operation observation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryOperation {
pub destination_address: u64,
pub is_write: bool,
}

/// Binary metadata fact
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BinaryInfo {
pub format: Arc<str>,
pub arch: Arc<str>,
pub entry_point: u64,
pub file_size: u64,
}

/// Security flags fact
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecurityFlags {
pub flag_name: Arc<str>,
pub flag_value: Arc<str>,
}

/// Section information fact
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SectionInfo {
pub name: Arc<str>,
pub is_executable: bool,
pub is_writable: bool,
}

/// Import/symbol fact
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImportInfo {
pub symbol: Arc<str>,
pub library: Option<Arc<str>>,
}

/// Symbolic execution query request
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SymQueryRequest {
pub query_id: String,
pub artifact_id: String,
pub addr: u64,
pub kind: String,
pub params: String,
}

/// Symbolic execution query result
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SymQueryResult {
pub query_id: String,
pub sat: bool,
pub summary: String,
pub witness: Option<String>,
}
