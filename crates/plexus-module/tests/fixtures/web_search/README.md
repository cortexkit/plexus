# web_search fixtures

| File | Provenance | Source |
| --- | --- | --- |
| `exa_search_reply.json` | **doc_derived** | Exa's published OpenAPI spec for `POST /search` (`https://exa.ai/docs/reference/search`, "Exa Public API" 2.0.0), read 2026-09-28. |

No live Exa key is available to the test suite, so this is not a captured
reply. It is built from the documentation and nothing in it was observed on
the wire.

- `requestId`, `resolvedSearchType`, `costDollars` and the first result are
  the `200` response example from the spec, copied field for field.
- The second result is constructed in the documented `SearchResultOutput`
  shape to cover the two cases the example does not: a result with no
  `publishedDate` and no `highlights`, so the mapping must omit
  `published_at` and fall back to the start of `text` for the excerpt. Its
  `text` is the endpoint description from the same spec.

If a real reply is ever captured, add it beside this file with its own row
here rather than replacing this one.
