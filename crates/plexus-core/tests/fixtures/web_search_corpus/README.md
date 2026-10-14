# Synthetic web-search corpus

`synthetic.jsonl` contains 232 invented searches about paper kites, lanterns and
fictional packages. No query, caller or timestamp was copied from deployment
logs. The `query`, `result_count`, `caller` and `at` fields describe each search;
`case`, `edge`, `include_domains`, `expected_rule` and
`documentation_or_discussion_candidate` explicitly describe each test case.
There are no vendor calls or credentials involved.

## Test inventory and expectations

The only test loading the `web_search_corpus` fixture directory is
`web_search::code_lookup::tests::synthetic_corpus_classification_matches_explicit_decisions`.
It asserts:

- Every query and included-domain list produces its row's explicit
  `expected_rule`, or an allow decision when that field is null.
- Case identifiers are unique and the corpus has 150–300 rows.
- Every refusal is listed exactly once in `refusal_review.jsonl`, with its
  1-based corpus line, identical query, rule and documentation-candidate flag.
  No allowed query appears in that inventory and no invented line remains.
- `documentation_review.jsonl` is exactly the ordered subset of refusals whose
  candidate flag is true. The flag is an authored review classification, not a
  claim that targeted documentation pages should be allowed.
- Observed category counts equal the explicit per-row expected counts. Every
  guard category and all nine edge groups below are present.

## Coverage

| Edge group | Rows | Cases |
| --- | ---: | --- |
| source-target | 28 | GitHub roots, blob, tree, raw, commit, commits and compare paths; `site:`, HTTP, HTTPS and scheme-less targets |
| registry-target | 64 | Raw GitHub, raw Gists, docs.rs, crates.io, lib.rs, pkg.go.dev, npm and PyPI; query strings and fragments |
| discussion-target | 48 | Allowed GitHub issues, PRs, discussions, releases, wiki and actions paths, with and without numbers |
| host-mention | 18 | All nine hosts named in prose without a target |
| hex-boundary | 32 | Bare SHA/checksum tokens of lengths 40/64; punctuation, labels and underscore boundaries; non-exact and longer runs |
| authority | 10 | Ports, userinfo, both, mixed case/`www`, allowed issues and lookalike userinfo on an unrelated actual host |
| include-domain | 18 | Plain and mixed-case/`www` included hosts, package-path requirements and GitHub targets in query text |
| precedence | 4 | Included-domain priority, first targeted host and targeted host before hashes; allowed discussion plus hash |
| documentation | 10 | Ordinary questions, unrelated documentation sites, registry search pages and incomplete/lookalike GitHub targets |

The explicit decision breakdown is **121 refused / 111 allowed**: GitHub
repositories 33, raw GitHub 11, Gist GitHub 10, docs.rs 11, crates.io 11, lib.rs 10,
pkg.go.dev 10, npm packages 8, PyPI projects 8 and exact hex tokens 9. Every
refusal category is represented. The classifier does not
produce these expectations or the review inventories.
