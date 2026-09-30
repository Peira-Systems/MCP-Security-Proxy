#!/usr/bin/env bash
# Shared watermark patterns for the pre-commit and commit-msg hooks.
# Kept narrow and attribution-shaped on purpose: this repo's own docs
# legitimately talk about Claude/Anthropic, so we only match lines that
# look like AI-authorship watermarks, never a bare mention of the name.

# Extended-regex alternatives (used with grep -E / sed -E).
WATERMARK_PATTERNS=(
  '[Gg]enerated (with|by) (\[)?(Claude|AI)\b'
  '[Cc]o-[Aa]uthored-[Bb]y:[[:space:]]*Claude\b'
  '[Cc]laude-[Ss]ession:[[:space:]]*https?://'
  'https?://claude\.ai/code/session_[A-Za-z0-9_-]+'
  '[Ww]ritten by (Claude|AI)\b'
  '<!--[[:space:]]*AI-generated[[:space:]]*-->'
  '🤖 [Gg]enerated with'
)

# Builds a single -E-compatible alternation from WATERMARK_PATTERNS.
watermark_regex() {
  local IFS='|'
  echo "${WATERMARK_PATTERNS[*]}"
}
