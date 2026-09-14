;; Hermetic W2 fixture: a static "echo" Wasm plugin used only to prove the
;; alloc/handle transport (docs/plugin-protocol.md §5.4) end to end --
;; Registry spawn, manifest handshake, and a live request/4 round trip.
;; It ignores its input entirely and always returns the same canned response,
;; which is deliberately shaped to double as both a valid Manifest (for the
;; initialize handshake) and a valid Decision-ish result (for a plain
;; request/4 call) -- proves the transport, not real dispatch logic. `handle`
;; returns a single pointer to an 8-byte {ptr,len} header, not a 2-value
;; return -- see docs/plugin-protocol.md §5.4.1 for why.
(module
  (memory (export "memory") 1)
  (data (i32.const 8) "{\"result\":{\"capabilities\":{\"scanner\":{\"canBlock\":false,\"dataNeeds\":[],\"failMode\":\"fail_open\",\"phases\":[\"discovery\",\"post_call\"],\"timeoutMs\":500}},\"findings\":[],\"plugin\":{\"name\":\"wasm-echo-scanner\",\"version\":\"0.1.0\"},\"protocolVersion\":\"0.1\",\"verdict\":\"allow\"}}")
  (data (i32.const 2048) "\08\00\00\00\03\01\00\00")
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
  (func $handle (export "handle") (param $in_ptr i32) (param $in_len i32) (result i32)
    i32.const 2048))
