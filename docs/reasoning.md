# Explainable authorization reasoning

AuthzLedger separates factual explanations from optional AI commentary. `explain_graph(graph)` is entirely offline: it explains the intended, calculated-policy and observed layers for every configured boundary and cites the graph edge, contract case, control prerequisites and available evidence hashes. These explanations come from deterministic graph facts. They are not labelled AI.

The result has `kind: authorization-explanation`, `schema_version: 1` and `decision_authority: deterministic-contract-and-observation`. The input graph must pass schema, source-binding, hash and internal observation consistency checks before any explanation or model request. The result retains the graph and contract SHA-256 digests. Every explanation includes `edge_id`, `case_id`, `states`, `outcome`, `assessment`, `content_evidence`, `positive_control_anchor_declared`, `text`, `citations`, `control_prerequisites` and the existing graph findings. Unknown or blocked observations remain unknown. A success status alone does not establish access to protected content. A denial status accompanied by a failed configured absence check is explained as a response-body boundary failure.

## Optional local model

The optional integration sends one request to an explicitly configured local Ollama `/api/generate` endpoint. It never selects a server, installs a model or downloads model weights. The operator must supply an already available model and a trusted local daemon.

```json
{
  "origin": "http://127.0.0.1:11434",
  "model": "your-installed-local-model:latest",
  "timeout_seconds": 10,
  "max_response_bytes": 65536
}
```

```python
from authzledger.reasoning import explain_graph

explanation = explain_graph(graph, model_config=config)
```

A declared positive-control anchor means that the contract requires a positive control; its presence alone does not prove that control succeeded.

Only literal loopback IP addresses are permitted. `localhost` is pinned to `127.0.0.1` without DNS resolution. IPv6 loopback is supported. The origin must use HTTP and must not contain credentials, a non-root path, query parameters or a fragment. Proxy environment variables and redirects are ignored. Authentication headers, cookies and ambient credentials are never used. Graph content cannot configure the model connection.

The request has a 32 KiB upper bound, a total socket deadline of at most 30 seconds and a response-body bound of at most 64 KiB. The default deadline is 10 seconds; operators may lower it. The deadline covers connection, response headers and body, including servers that continuously send small pieces of data. Compressed responses are rejected.

Only enum-valued decisions, outcomes, assessments, content-evidence classifications, declared-control-anchor booleans, control relationships and recognized finding categories are shared. Per-call IDs such as `e0001` replace real identifiers. Target URLs, paths, identity names, case IDs, raw responses, credentials, policy input, finding narratives, response digests and evidence hashes are excluded. At most 64 edges are shared, with omitted edges reported explicitly. All deterministic explanations remain available regardless of this limit. The local daemon is a separate trust boundary: AuthzLedger cannot prevent that daemon from retaining or forwarding requests. Choose a locally hosted model and review the daemon's configuration.

## Output and authority

AI output is a structured set of plain-text notes. Each note must identify and cite supplied opaque edge IDs; citations are mapped back to the existing graph. Fabricated references, unknown fields, duplicate edge notes, excessive text, excessive note counts, markup and control characters are rejected. Nothing from the model is executed or treated as trusted HTML.

`ai.status` is `disabled`, `generated` or `error`. The integration always sets `advisory_only: true` and `claims_verified: false`; every generated note has `untrusted: true`. Model and source labels are separate from factual explanations. A missing daemon, invalid response, oversized body, timeout or invalid citation produces a sanitized error category and leaves the deterministic result intact. Server responses and detailed network exceptions are never copied into error messages.

Valid citations establish that a referenced edge exists. They do not establish that the model's interpretation is true. The model cannot change graph states, contract assertions, policy decisions, runtime findings, control dependencies, execution outcomes, exit status or evidence. For example, commentary that says “all boundaries are protected” has no effect on a recorded `unexpected-access` finding. Any extra field that attempts to override a decision is rejected.

In Studio, local inference should require operator opt-in against a fixed server-side configuration. Browser input must never select the model origin or arbitrary local ports. Render notes as escaped plain text. Evidence review, retests and CI gates use deterministic outputs, independently of model availability.

## Validation

`python -m unittest tests.test_reasoning -v` exercises real dummy loopback HTTP inference, pseudonymization, preserved control relationships, unavailable endpoints, invalid and fabricated citations, attempts to introduce decision fields, oversized bodies, redirects, proxy isolation and total header/body deadlines. These tests validate the integration boundary. They do not claim a language model produces consistently correct authorization analysis.
