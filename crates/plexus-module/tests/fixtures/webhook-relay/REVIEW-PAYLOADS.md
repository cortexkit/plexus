# Review webhook payloads

`review-submitted.json` and `review-comment-created.json` are synthetic payloads
using the documented GitHub webhook object shapes, not live captures or relay
wire vectors. All account names, ids, text and commit hashes are invented.

Sources:
- https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request_review
- https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request_review_comment

The fixtures retain the fields consumed by Plexus, including the nested
`pull_request`, `review` / `comment`, `repository`, `sender` and `installation`.
Tests wrap these bodies in relay frames separately.
