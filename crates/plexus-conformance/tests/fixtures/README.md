# Anonymized GitHub list captures

These fixtures retain the shapes captured from GitHub's
`api.githubcopilot.com/mcp/readonly` server: a wrapped issues response with
`totalCount` and `pageInfo`, and a bare pull-request array. The issues response
was captured on 2026-08-07 from `rust-lang/rust` and trimmed to the fields used
by the shipped poll shape. The pull-request fixture was captured from the same
server and session.

Both captures have been anonymized: all titles describing real work were
replaced with invented paper-kite workshop titles. These trimmed shapes contain
no human account, name or email fields. All fields and types, issue/PR numbers,
states, timestamps, URLs and pagination values are unchanged. The tests still
replay the captured wire shapes, not verbatim captured prose.
