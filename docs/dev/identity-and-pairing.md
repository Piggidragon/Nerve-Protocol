# Identity and pairing

Exact formats are in [spec/protocol.md](spec/protocol.md) §2 and §3.

## Identities

| Who | Identity |
|---|---|
| Center | A random id (UUID-shaped) and a name, both made on its first start. A TLS key and a self-signed certificate. Its **pin** is the base64url SHA-256 of the certificate's public key info (43 characters) |
| Node | One Ed25519 key pair **per center**, made at pairing and kept in `keys/<name>.key` (mode 0600), or in the system keyring with `machine.secret_storage = "keyring"`. The **node id** is the base32 of the first 16 bytes of the SHA-256 of the public key (26 characters). The node name is 1 to 32 characters of `a-z`, `0-9` and `-`, from the host name by default |
| Harness | A token, from `--harness-token` or made in the web UI. It is local to the center host |

Because the key is per center, two centers see two unrelated ids for the same
machine. They cannot link the machine across trust domains.

A node has no bearer token. A config copied without its private key cannot
connect. A copied key is caught by the [one-link rule](node-link.md#one-live-link).

The center may give a node a display name. That name never goes back to the
node.

## Pairing

1. In the center's web UI, **Pair a machine** makes a one-time code and shows
   the link. The code lasts 10 minutes by default (up to 24 hours), allows 10
   tries and works once.
   `nerve://pair?center=<percent-encoded URL>&code=<code>&pin=<pin>`
2. On the node: `nerve-node center add '<link>'`. The node parses the link
   strictly and shows the center's address, plus the policy the new pairing
   starts with (mode `allowlist`, no rule, settings grant `off`). It stores
   nothing before the owner confirms.
3. The node makes a key pair for this center and sends
   `POST <center>/nerve/v0/pair` with `{code, name, platform, arch,
   public_key}` over TLS, checked against the pin.
4. The center answers `{center_id, center_name, node_id}` and stores the public
   key. The node stores the pairing.

The center computes the `node_id` from the public key itself.

### The link

- `center` is an `https://` URL, or `http://` to a loopback address. It has no
  user info, query or fragment and no `.` or `..` path segments.
- `pin` is optional. Without it the node checks the certificate against the
  system roots.
- The parser refuses unknown keys, a key given twice, bad percent escapes, a
  fragment and a link over 4096 bytes.
- Over plain `http`, the node on Linux checks that the listening socket belongs
  to its own user.

### Answers to a pair request

| Status | Meaning |
|---|---|
| 200 | Paired |
| 400 | Malformed request or name |
| 403 | Code unknown, used, expired or out of tries |
| 409 | Another node has this name, or this key is paired |

## Unpairing

Both sides can end a pairing.

- **From the node.** `nerve-node center rm` sends `bye {reason: "unpaired"}` if
  a link is up, and deletes the key. The center forgets the node when it sees
  that.
- **From the center.** Removing the node in the web UI sends
  `bye {reason: "revoked"}` and closes the link. The node stops dialling that
  center and keeps the key until `center rm`, so the owner can see what
  happened.
