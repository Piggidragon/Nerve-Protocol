# Conformance

The conformance suite lives in `crates/nerve-conformance`. It has three
parts; every check names the section of [protocol.md](protocol.md) it tests,
so a failure points at the rule that was broken.

| Part | Checks | Acts as | State in 0.0.1 |
|---|---|---|---|
| center | a center | the echo node | runs |
| node | a node | a fake center | runs |
| harness | the MCP server surface a harness sees | a center | skeleton: lists its checks, runs none |

Harnesses integrate through MCP only in 0.0.1, so the harness part checks the
MCP server surface. Native plugins are a backlog item.

## Running it

There is no runner binary in 0.0.1. The parts are library calls that return a
report, and `cargo test -p nerve-conformance` runs them:

- `tests/self_test.rs`: the center part against the fake center and the node
  part against the echo node. These check the suite itself.
- `tests/e2e.rs`: the center part against a real `nerve-center`, the node part
  against a real `nerve-node`, and `nerve-center` with `nerve-node` against each
  other (pairing, link, tools over MCP, approvals, settings, audit).

To check another implementation, call `center_part::run(&pair_link)` with a
fresh pairing link of that center, or `node_part::run(start)` with a closure
that pairs the node under test with the link it is handed and starts it.

## Center part

| § | Check |
|---|---|
| 3.2 | a wrong pairing code is answered with 403 |
| 3.2 | a pair request with an unknown field is answered with 400 |
| 3.2 | a good pair request is answered with 200 |
| 2.2 | the node id is base32 of SHA-256 of the key |
| 3.2 | a used code is refused |
| 4.1 | an unknown node is answered with 401 |
| 4.2 | the first frame is a challenge |
| 4.2 | a wrong signature closes the link |
| 1 | a version mismatch closes with `unsupported_version` |
| 4.2 | a good hello gets a welcome for version "0" |
| 4.2 | the center fetches the descriptor after welcome |

## Node part

| § | Check |
|---|---|
| 3.2 | the node pairs |
| 2.2 | the node name is 1 to 32 of `a-z`, `0-9` and `-` |
| 4.1 | the node dials the center |
| 4.1 | the `Nerve-Node` header names the paired node id |
| 4.2 | the hello is signed and names version "0" |
| 6 | describe full returns a well-formed descriptor |
| 5.1 | describe capability without cap is `invalid_args` |
| 5.2 | an unknown method is `method_not_found` |
| 5.3 | invoke of an unknown capability is `unknown_capability` |
| 5.2 | an unknown ctx field is `invalid_args` |
| 7.4 | `approvals.list` answers with a list |
| 4.5 | after `bye revoked` the node does not dial again |

## Not covered yet

Binary frames and blobs (§5.4), limits (§5.5), the duplicate-link rule (§4.3),
liveness timing (§4.4), back-off (§4.6) and proxies (§4.7) have unit tests in
the implementations but no conformance checks yet.
