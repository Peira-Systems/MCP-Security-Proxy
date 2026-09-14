;; Hermetic W3 fixture: a static "always deny" Wasm policy used only to prove
;; the DENY path (docs/plugin-protocol.md §5.4) flows correctly through
;; Pipeline -- short-circuit on pre_call, response withholding on post_call --
;; not a real policy. See wasm_echo_scanner.wat for the always-allow sibling.
(module
  (memory (export "memory") 1)
  (data (i32.const 8) "{\"result\":{\"capabilities\":{\"policy\":{\"canMutate\":[],\"dataNeeds\":[],\"failMode\":\"fail_closed\",\"phases\":[\"pre_call\",\"post_call\"],\"timeoutMs\":500}},\"findings\":[],\"plugin\":{\"name\":\"wasm-deny-policy\",\"version\":\"0.1.0\"},\"protocolVersion\":\"0.1\",\"reason\":\"denied by wasm-deny-policy (test fixture)\",\"severity\":\"high\",\"verdict\":\"deny\"}}")
  (global $bump_offset (mut i32) (i32.const 4096))
  (func $alloc (export "alloc") (param $size i32) (result i32)
    (local $ptr i32)
    global.get $bump_offset
    local.set $ptr
    global.get $bump_offset
    local.get $size
    i32.add
    global.set $bump_offset
    local.get $ptr)
  (func $handle (export "handle") (param $in_ptr i32) (param $in_len i32) (result i32 i32)
    i32.const 8
    i32.const 326))
