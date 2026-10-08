//! The bridge from a [`Fact`] set to HEL's attribute lookup.
//!
//! HEL evaluates a condition by asking a [`HelResolver`] for the value of each `object.field`
//! it meets. This module answers those questions out of a fact set, which is the whole of the
//! engine's coupling to HEL: facts in, attribute lookups out, no types shared between the two
//! beyond HEL's [`Value`].

use crate::facts::*;
use hel::{HelResolver, Value};
use std::collections::HashSet;

/// Answers HEL attribute lookups from a `HashSet<Fact>`.
///
/// Borrows the fact set rather than owning it, so the engine can build a resolver per rule
/// round and let it drop again. The object names a condition may use are fixed by this
/// resolver: `binary`, `security`, `section`, `import`, `TaintFlow`, `FunctionCall`,
/// `MemoryOperation`, `OnnxModelOutput`, `TriggeredRule`, and whatever namespace a
/// [`Fact::Custom`] chose.
pub struct FactSetResolver<'a> {
    facts: &'a HashSet<Fact>,
}

impl<'a> FactSetResolver<'a> {
    /// A resolver over `facts`.
    #[must_use]
    pub fn new(facts: &'a HashSet<Fact>) -> Self {
        Self { facts }
    }
}

impl<'a> HelResolver for FactSetResolver<'a> {
    /// The value of `object.field`, or `None` if no fact provides it.
    ///
    /// Each fact is tested against the object name its variant is reached by, so a condition
    /// only sees the fact kinds it names. `None` is a normal answer - HEL evaluates it as a
    /// null, and a comparison against it is false.
    ///
    /// A fact set holding two facts that provide the *same* attribute has no defined answer:
    /// the fact set is a `HashSet`, so which one is found first depends on its iteration order.
    /// Supplying one fact per attribute per subject is the caller's contract; if several apply,
    /// treat the resolved value as one of them rather than a specific one.
    fn resolve_attr(&self, object: &str, field: &str) -> Option<Value> {
        for fact in self.facts {
            match fact {
                Fact::TaintFlow(flow) if object == "TaintFlow" => match field {
                    "source" => return Some(Value::String(flow.source.clone())),
                    "sink" => return Some(Value::String(flow.sink.clone())),
                    _ => {}
                },

                Fact::FunctionCall(call) if object == "FunctionCall" => match field {
                    "name" => return Some(Value::String(call.name.clone())),
                    "properties" => {
                        return Some(Value::List(
                            call.properties
                                .iter()
                                .map(|s| Value::String(s.clone()))
                                .collect(),
                        ));
                    }
                    "arguments" => {
                        return Some(Value::List(
                            call.arguments
                                .iter()
                                .map(|s| Value::String(s.clone()))
                                .collect(),
                        ));
                    }
                    _ => {}
                },

                Fact::MemoryOperation(op) if object == "MemoryOperation" => match field {
                    "destination_address" => {
                        return Some(Value::Number(op.destination_address as f64));
                    }
                    "is_write" => return Some(Value::Bool(op.is_write)),
                    _ => {}
                },

                // Read as `binary`, not `BinaryInfo`.
                Fact::BinaryInfo(info) if object == "binary" => match field {
                    "format" => return Some(Value::String(info.format.clone())),
                    "arch" => return Some(Value::String(info.arch.clone())),
                    "entry_point" => return Some(Value::Number(info.entry_point as f64)),
                    "file_size" => return Some(Value::Number(info.file_size as f64)),
                    _ => {}
                },

                Fact::SecurityFlags(flags) if object == "security" => {
                    if field == flags.flag_name.as_ref() {
                        return Some(Value::String(flags.flag_value.clone()));
                    }
                }

                Fact::SectionInfo(section) if object == "section" => match field {
                    "name" => return Some(Value::String(section.name.clone())),
                    "is_executable" => return Some(Value::Bool(section.is_executable)),
                    "is_writable" => return Some(Value::Bool(section.is_writable)),
                    _ => {}
                },

                Fact::ImportInfo(import) if object == "import" => match field {
                    "symbol" => return Some(Value::String(import.symbol.clone())),
                    // No library is no answer, which HEL reads as a null.
                    "library" => return import.library.as_ref().map(|l| Value::String(l.clone())),
                    _ => {}
                },

                Fact::Custom {
                    namespace,
                    key,
                    value,
                } if object == namespace.as_ref() => {
                    if field == key.as_ref() {
                        // A numeric value resolves as a Number, so a rule can apply an ordering
                        // operator to it (`asm.gadgets > 200`). Anything else stays a String, so
                        // `== "present"` still works. A value that is not a number is not an
                        // error.
                        if let Ok(n) = value.parse::<f64>() {
                            return Some(Value::Number(n));
                        }
                        return Some(Value::String(value.clone()));
                    }
                }

                Fact::OnnxModelOutput(v) if object == "OnnxModelOutput" => {
                    return Some(Value::String(v.clone()));
                }

                Fact::TriggeredRule(id) if object == "TriggeredRule" => {
                    return Some(Value::String(id.clone()));
                }

                // A fact kind with no attribute lookup for this object - or a variant the
                // resolver has no mapping for - is not an answer to this question.
                _ => {}
            }
        }
        None
    }
}
