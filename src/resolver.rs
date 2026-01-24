//! Adapter to implement HelResolver for Shapash Fact sets

use crate::facts::*;
use hel::{HelResolver, Value};
use std::collections::HashSet;

/// Adapter that implements HelResolver over a `HashSet<Fact>`
///
/// This provides the bridge between Shapash domain facts and the HEL evaluation engine.
pub struct FactSetResolver<'a> {
facts: &'a HashSet<Fact>,
}

impl<'a> FactSetResolver<'a> {
pub fn new(facts: &'a HashSet<Fact>) -> Self {
Self { facts }
}
}

impl<'a> HelResolver for FactSetResolver<'a> {
fn resolve_attr(&self, object: &str, field: &str) -> Option<Value> {
// Iterate through facts and find matching attributes
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
call.properties.iter().map(|s| Value::String(s.clone())).collect(),
))
}
"arguments" => {
return Some(Value::List(call.arguments.iter().map(|s| Value::String(s.clone())).collect()))
}
_ => {}
},

Fact::MemoryOperation(op) if object == "MemoryOperation" => match field {
"destination_address" => return Some(Value::Number(op.destination_address as f64)),
"is_write" => return Some(Value::Bool(op.is_write)),
_ => {}
},

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
"library" => return import.library.as_ref().map(|l| Value::String(l.clone())),
_ => {}
},

Fact::Custom { namespace, key, value } if object == namespace.as_ref() => {
if field == key.as_ref() {
return Some(Value::String(value.clone()));
}
}

Fact::OnnxModelOutput(v) if object == "OnnxModelOutput" => {
return Some(Value::String(v.clone()));
}

Fact::TriggeredRule(id) if object == "TriggeredRule" => {
return Some(Value::String(id.clone()));
}

_ => {}
}
}
None
}
}
