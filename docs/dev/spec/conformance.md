# Conformance

The conformance suite lives in `crates/nerve-conformance`. It has four
parts; every check names the section of [protocol.md](protocol.md) it tests
(the provider part: of [node-local.md](node-local.md)), so a failure points
at the rule that was broken.

| Part | Checks | Acts as | State |
|---|---|---|---|
| center | a center | the echo node | runs |
| node | a node | a fake center | runs |
| harness | the MCP server surface a harness sees | a center | skeleton: lists its checks, runs none |
| provider | a node's capability provider attach ([node-local.md §7](node-local.md#7-capability-providers)) | a center and a provider | runs (Unix) |

Harnesses integrate through MCP only, so the harness part checks the
MCP server surface. Native plugins are a backlog item.

## Running it

There is no runner binary. The parts are library calls that return a
report, and `cargo test -p nerve-conformance` runs them:

- `tests/self_test.rs`: the center part against the fake center and the node
  part against the echo node. These check the suite itself.
- `tests/e2e.rs`: the center part against a real `nerve-center`, the node part
  and the provider part against a real `nerve-node`, and `nerve-center` with
  `nerve-node` against each other (pairing, link, tools over MCP, folders and
  rules, settings, audit).

To check another implementation, call `center_part::run(&pair_link)` with a
fresh pairing link of that center, or `node_part::run(start)` with a closure
that pairs the node under test with the link it is handed and starts it.

The closure returns a `Setup`. With `folder` (an empty folder on the node, in
wire form) and the settings grant `write` for the fake center, the node part
also checks the profiles: it writes its own policy with `settings.set` (that
folder read-write and one exact command in `allow`, one in `sudo_allow`) and checks fs, exec, the audit
event and the sudo switch. The sudo switch must be off when the part starts.
It sends one wrong sudo password, so a node with a real `sudo` logs one failed
attempt; with `sudo_password` it also turns sudo on and off once. The e2e test
points the node at a fake `sudo` (`machine.sudo_path`) for this.

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
| 4.5 | after `bye revoked` the node does not dial again |

With a `Setup::folder`, before `bye revoked`:

| § | Check |
|---|---|
| 7.4 | settings get returns document and version |
| 7.4 | settings set with a stale `if_version` is `conflict` |
| 7.4 | settings set applies a document |
| 7.2 | fs read returns what fs write wrote, with the same etag |
| 7.2 | fs read outside the allowed folder is `forbidden` |
| 7.3 | exec run of a command an allow rule names runs |
| 7.3 | a deny rule wins over an allow rule from the next call on |
| 7.3 | exec run of a command nothing allows is `forbidden` |
| 7.5 | a refusal emits `audit` `decision` `forbidden` |
| 7.4.1 | sudo is off at first |
| 7.4.1 | with sudo off, a sudo command on the sudo allow list is `forbidden` |
| 7.4.1 | `sudo-offer` is signed with the node's key for this center |
| 7.4.1 | a wrong sudo password is `invalid_args` and sudo stays off |

With a `Setup::sudo_password` as well:

| § | Check |
|---|---|
| 7.4.1 | the right sudo password turns sudo on |
| 7.4.1 | with sudo on, a sudo command on the sudo allow list runs |
| 7.4.1 | with sudo on, a sudo command the sudo allow list does not name is `forbidden` |
| 7.4.1 | sudo off turns sudo off |
| 7.4.1 | a replayed sealed password is `invalid_args` and sudo stays off |
| 7.4.1 | no frame the node sent carries the sudo password |

## Provider part

`provider_part::run(start)` checks a node's provider attach on Linux. The
closure pairs the node with the link it is handed, gives that center the
settings grant `write`, allows the program that runs the part
(`std::env::current_exe()`) in `providers.allowed` under `Setup::provider`,
and starts the node; `Setup::socket` is its control socket. The part writes its
own policy with `settings.set` (`user` mode and a deny rule for `echo.shout`
before the provider comes, allow rules for `echo.say` and `echo.fail` once it
is there) and attaches an `echo` provider with the actions `say`, `shout` and
`fail`. Every check names node-local §7.

| Check |
|---|
| a center may not allow a capability no provider offers |
| a program `providers.allowed` does not name is refused |
| an allowed provider attaches |
| a second provider of the same name is refused |
| the node tells the center that its descriptor changed |
| the descriptor lists the capability with its provider |
| a center may allow an offered capability that does not sense, and the descriptor follows |
| a call the policy allows reaches the provider and its answer comes back |
| a provider's error comes back with its code |
| a call the policy refuses never reaches the provider |
| when the provider exits its capability leaves the descriptor |
| a call to a provider that left is `unknown_capability` |

## Not covered

Binary frames and blobs (§5.4), limits (§5.5), the duplicate-link rule (§4.3),
liveness timing (§4.4), back-off (§4.6) and proxies (§4.7) have unit tests in
the implementations but no conformance checks.
