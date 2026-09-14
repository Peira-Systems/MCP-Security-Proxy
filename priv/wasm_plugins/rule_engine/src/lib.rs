//! `rule-engine-wasm` -- the W4 reference Wasm plugin (docs/wasm-plugin-plan.md).
//!
//! A port of `PhoenixElxirBeam.MCP.Plugins.RuleEngine`'s match/decision logic to
//! `wasm32-wasip1`, speaking the guest ABI in `docs/plugin-protocol.md` §5.4. It is
//! deliberately a *port*, not a reimplementation from the spec: every predicate and every
//! branch here has a named counterpart in `lib/phoenix_elxir_beam/mcp/plugins/rule_engine.ex`,
//! and the two are checked for identical verdicts across a shared test corpus
//! (`rule_engine_wasm_parity_test.exs`) -- that parity, not "it compiles," is what makes this
//! plugin done. Pure computation, no I/O of any kind, no `unsafe`.
//!
//! Build: `cargo build --release --target wasm32-wasip1` from this directory, then copy
//! `target/wasm32-wasip1/release/rule_engine_wasm.wasm` to `priv/wasm_plugins/rule_engine.wasm`
//! (see `build.sh` alongside this file for the one-line version).

use serde_json::{json, Value};

// -- guest ABI (docs/plugin-protocol.md §5.4.1) -----------------------------

/// Reserves `size` bytes and returns a pointer to them. Each Wasm instance this project's
/// `WasmRunner` spins up serves exactly one call before being discarded (see the runner's
/// moduledoc), so nothing here is ever freed -- there is nothing to leak across calls, only
/// within one already-throwaway instance.
#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    let mut buf = Vec::<u8>::with_capacity(size.max(0) as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr as i32
}

/// Processes one request envelope and returns a pointer to an 8-byte header
/// (`[response_ptr: u32 LE, response_len: u32 LE]`) locating the actual response bytes.
///
/// Not `(i32, i32)` multi-value return: `extern "C"` on this target lowers a tuple return
/// to an *unspecified* ABI (confirmed while building this plugin — `rustc` itself warns
/// tuples have "unspecified layout" for `extern "C"`, and empirically it turned out to be
/// neither genuine Wasm multi-value nor a predictable sret parameter position). A single
/// `i32` return pointing to a manually-written header sidesteps the ambiguity entirely and
/// is portable to any toolchain, not just ones that happen to agree with Rust's choice here.
#[no_mangle]
pub extern "C" fn handle(in_ptr: i32, in_len: i32) -> i32 {
    let input = unsafe { std::slice::from_raw_parts(in_ptr as *const u8, in_len.max(0) as usize) };

    let envelope = match serde_json::from_slice::<Value>(input) {
        Ok(v) => dispatch(&v),
        Err(e) => error_envelope(-32700, &format!("invalid JSON: {e}")),
    };

    respond(&envelope)
}

fn respond(envelope: &Value) -> i32 {
    let body = envelope.to_string().into_bytes().into_boxed_slice();
    let body_len = body.len() as u32;
    let body_ptr = Box::into_raw(body) as *mut u8 as u32;

    let mut header = Box::new([0u8; 8]);
    header[0..4].copy_from_slice(&body_ptr.to_le_bytes());
    header[4..8].copy_from_slice(&body_len.to_le_bytes());
    Box::into_raw(header) as *mut u8 as i32
}

fn error_envelope(code: i32, message: &str) -> Value {
    json!({"error": {"code": code, "message": message}})
}

// -- method dispatch ----------------------------------------------------------

fn dispatch(req: &Value) -> Value {
    match req.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({"result": manifest()}),
        Some("call/evaluate") => {
            let ctx = req.get("params").and_then(|p| p.get("context"));
            match ctx {
                Some(ctx) => json!({"result": evaluate(ctx)}),
                None => error_envelope(-32602, "missing params.context"),
            }
        }
        Some(other) => error_envelope(-32601, &format!("method not found: {other}")),
        None => error_envelope(-32600, "missing method"),
    }
}

fn manifest() -> Value {
    json!({
        "protocolVersion": "0.1",
        "plugin": {
            "name": "rule-engine-wasm",
            "version": "0.1.0",
            "description": "Wasm port of rule-engine (docs/wasm-plugin-plan.md W4) -- \
                config-driven allow/deny/hold rules, first match wins."
        },
        "capabilities": {
            "policy": {
                "phases": ["pre_call"],
                "dataNeeds": ["session.seenTags", "session.taint"],
                "timeoutMs": 50,
                "failMode": "fail_closed"
            }
        }
    })
}

// -- rule evaluation -- ports RuleEngine.evaluate/2 + its private helpers -----

fn evaluate(ctx: &Value) -> Value {
    let rules = ctx
        .pointer("/pluginConfig/rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    match rules.iter().find(|rule| matches_rule(rule, ctx)) {
        None => json!({"verdict": "allow"}),
        Some(rule) => to_decision(rule),
    }
}

fn to_decision(rule: &Value) -> Value {
    let reason = rule
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("blocked by rule-engine-wasm");

    match rule.get("action").and_then(Value::as_str) {
        Some("deny") => json!({"verdict": "deny", "severity": severity(rule), "reason": reason}),
        // severity "high" is not a choice this rule makes -- PhoenixElxirBeam.MCP.Decision
        // .hold/2 hardcodes it unconditionally on the Elixir side (it isn't even a rule
        // field), so this is a literal port of that, not a real severity computation.
        Some("hold") => json!({
            "verdict": "hold",
            "severity": "high",
            "reason": reason,
            "hold": {
                "prompt": rule.get("prompt").and_then(Value::as_str).unwrap_or(reason),
                "timeoutMs": rule.get("timeout_ms").and_then(Value::as_i64).unwrap_or(120_000),
                "onTimeout": "deny"
            }
        }),
        _ => json!({"verdict": "allow"}),
    }
}

fn severity(rule: &Value) -> &'static str {
    match rule.get("severity").and_then(Value::as_str) {
        Some("critical") => "critical",
        Some("medium") => "medium",
        Some("low") => "low",
        _ => "high",
    }
}

fn matches_rule(rule: &Value, ctx: &Value) -> bool {
    match rule.get("match") {
        None => true,
        Some(m) => match m.as_object() {
            None => true,
            Some(obj) => obj.iter().all(|(key, value)| predicate(key, value, ctx)),
        },
    }
}

fn predicate(key: &str, value: &Value, ctx: &Value) -> bool {
    match key {
        "agent" => str_eq(agent(ctx), value),
        "agent_prefix" => match (agent(ctx), value.as_str()) {
            (Some(a), Some(p)) => a.starts_with(p),
            _ => false,
        },
        "tool" => str_eq(ctx.pointer("/call/toolName").and_then(Value::as_str), value),
        "server" => str_eq(ctx.pointer("/call/serverId").and_then(Value::as_str), value),
        "tool_tags_any" => tool_tags_any(value, ctx),
        // Elixir's clause head pattern-matches the literal `true` -- any other value
        // (false, a string, ...) falls through to the "unknown predicate" catch-all
        // below, i.e. never matches. Ported exactly, not just "truthy".
        "after_sensitive_read" if value == &Value::Bool(true) => {
            has_tag(ctx.pointer("/session/seenTags"), "sensitive_read")
        }
        "if_tainted" if value == &Value::Bool(true) => ctx
            .pointer("/session/taint/sources")
            .and_then(Value::as_array)
            .is_some_and(|sources| !sources.is_empty()),
        // An unknown predicate -- or an "after_sensitive_read"/"if_tainted" with a
        // non-true value -- never matches. Fail closed on operator typos.
        _ => false,
    }
}

fn agent(ctx: &Value) -> Option<&str> {
    ctx.pointer("/call/agentId").and_then(Value::as_str)
}

fn str_eq(actual: Option<&str>, expected: &Value) -> bool {
    matches!((actual, expected.as_str()), (Some(a), Some(e)) if a == e)
}

fn has_tag(tags: Option<&Value>, needle: &str) -> bool {
    tags.and_then(Value::as_array)
        .is_some_and(|arr| arr.iter().any(|t| t.as_str() == Some(needle)))
}

fn tool_tags_any(rule_tags: &Value, ctx: &Value) -> bool {
    let Some(rule_tags) = rule_tags.as_array() else {
        return false;
    };

    let call_tags: Vec<&str> = ctx
        .pointer("/call/tags")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    rule_tags
        .iter()
        .filter_map(Value::as_str)
        .any(|t| call_tags.contains(&t))
}
