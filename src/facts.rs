//! Domain-specific fact types for rule evaluation.
//!
//! A [`Fact`] is one observation about the subject being scored, and the fact set is the
//! engine's whole input: rules are HEL expressions over the attributes these facts expose.
//! [`FactSetResolver`](crate::FactSetResolver) is what maps a rule's `object.field` reference
//! onto one of them, so the object names in a rule — `binary`, `TaintFlow`, `import` — are
//! chosen here, in the resolver, not in the fact types themselves.
//!
//! The set holds facts by value and identity ([`Hash`] + [`Eq`]), so inserting the same fact
//! twice is a no-op — which is also why a fact carries no ordering: the engine sorts what it
//! reports rather than what it stores.

use std::sync::Arc;

/// A fact in the rule evaluation system.
///
/// Each variant is one kind of observation, and each is documented with the object name its
/// attributes are reached by in a condition. Facts are compared and hashed by value, so
/// duplicates collapse in a `HashSet`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Fact {
    /// A rule that has already fired, recorded during forward chaining.
    ///
    /// The engine inserts one of these when a rule triggers and skips any rule whose id is
    /// already present, so a rule fires once however many rounds it takes to reach a fixpoint.
    TriggeredRule(Arc<str>),
    /// A taint flow from a source to a sink. Attributes: `TaintFlow.source`, `TaintFlow.sink`.
    TaintFlow(TaintFlow),
    /// An observed function call. Attributes: `FunctionCall.name`, `.arguments`, `.properties`.
    FunctionCall(FunctionCall),
    /// An observed memory operation. Attributes: `MemoryOperation.destination_address`,
    /// `.is_write`.
    MemoryOperation(MemoryOperation),
    /// Text produced by an ONNX model. Attribute: `OnnxModelOutput`.
    OnnxModelOutput(Arc<str>),
    /// Binary metadata. Attributes: `binary.format`, `.arch`, `.entry_point`, `.file_size`.
    BinaryInfo(BinaryInfo),
    /// A security-relevant flag. Attribute: `security.<flag_name>` (the flag's own name is the
    /// field).
    SecurityFlags(SecurityFlags),
    /// A binary section. Attributes: `section.name`, `.is_executable`, `.is_writable`.
    SectionInfo(SectionInfo),
    /// An imported symbol. Attributes: `import.symbol`, `import.library`.
    ImportInfo(ImportInfo),
    /// A query handed to a symbolic-execution backend.
    ///
    /// Carried so a caller can put it in the set and read it back out; the engine treats it as
    /// data and does not send it anywhere. **No condition can read it**: the resolver has no
    /// mapping for this variant, so any `SymQueryRequest.<field>` reference resolves to a null.
    SymQueryRequest(SymQueryRequest),
    /// The result of such a query, on the same footing as [`SymQueryRequest`](Self::SymQueryRequest)
    /// — carried as data, not readable from a condition.
    SymQueryResult(SymQueryResult),
    /// An open-ended fact, under a caller-chosen object name.
    ///
    /// Reached as `<namespace>.<key>` in a condition. A value that parses as a number resolves
    /// as one, so `asm.gadgets > 200` works; anything else resolves as a string, so
    /// `asm.packer == "present"` keeps working.
    Custom {
        /// The object name the key is reached through.
        namespace: Arc<str>,
        /// The field name, under that object.
        key: Arc<str>,
        /// The value, as text.
        value: Arc<str>,
    },
}

/// A taint flow from a source to a sink.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaintFlow {
    /// Where the data came from.
    pub source: Arc<str>,
    /// The dangerous operation it reached.
    pub sink: Arc<str>,
}

/// An observed function call.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionCall {
    /// The callee's name.
    pub name: Arc<str>,
    /// The arguments, in call order.
    pub arguments: Vec<Arc<str>>,
    /// Free-form properties a caller attached (e.g. `["unchecked"]`).
    pub properties: Vec<Arc<str>>,
}

/// An observed memory operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryOperation {
    /// The address the operation acted on. Exposed to conditions as a number, so it is exact
    /// only up to 2^53 — beyond that a rule's comparison loses precision.
    pub destination_address: u64,
    /// `true` for a write, `false` for a read.
    pub is_write: bool,
}

/// Binary metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BinaryInfo {
    /// The container format, as the rule expects to spell it (e.g. `"ELF"`).
    pub format: Arc<str>,
    /// The instruction set (e.g. `"x86_64"`).
    pub arch: Arc<str>,
    /// The entry point's virtual address. Exact only up to 2^53 once it reaches a condition.
    pub entry_point: u64,
    /// The file's size in bytes, on the same caveat as `entry_point`.
    pub file_size: u64,
}

/// A security-relevant flag, addressed in a condition by the flag's own name.
///
/// `SecurityFlags { flag_name: "nx", flag_value: "true" }` is read as `security.nx`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecurityFlags {
    /// The field name the value is reached by.
    pub flag_name: Arc<str>,
    /// The flag's value, as text.
    pub flag_value: Arc<str>,
}

/// A binary section.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SectionInfo {
    /// The section's name (e.g. `".text"`).
    pub name: Arc<str>,
    /// Whether the section is marked executable.
    pub is_executable: bool,
    /// Whether the section is marked writable.
    pub is_writable: bool,
}

/// An imported symbol.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImportInfo {
    /// The symbol's name.
    pub symbol: Arc<str>,
    /// The library it came from, when known.
    ///
    /// When it is `None` the resolver answers nothing for `import.library`, which HEL
    /// evaluates as a null, so a comparison against it is false rather than an error.
    pub library: Option<Arc<str>>,
}

/// A query handed to a symbolic-execution backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SymQueryRequest {
    /// Identifies this query among the ones issued for an artifact.
    pub query_id: String,
    /// The artifact the query is about.
    pub artifact_id: String,
    /// The address the query starts from.
    pub addr: u64,
    /// What is being asked (e.g. `"overflow"`).
    pub kind: String,
    /// Any parameters, encoded by the caller.
    pub params: String,
}

/// The result of a symbolic-execution query.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SymQueryResult {
    /// The `query_id` of the [`SymQueryRequest`] this answers.
    pub query_id: String,
    /// Whether the query was satisfiable.
    pub sat: bool,
    /// A human-readable summary of the outcome.
    pub summary: String,
    /// A concrete input that satisfies the query, when one was produced.
    pub witness: Option<String>,
}
