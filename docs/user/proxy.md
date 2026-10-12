# Reach the center through a proxy

A node can dial its centers through an HTTP proxy. The proxy is one setting
for the whole node, for every center.

```sh
nerve-node proxy set http://proxy.example:3128
nerve-node proxy ls
nerve-node proxy rm
```

The node opens the TLS link to the center inside a `CONNECT` tunnel. The
center's pin is still checked on that inner link, so the proxy sees only TLS
records.

## A proxy that wants a login

Put the user name and password in the URL, or send extra header lines on the
`CONNECT` request:

```sh
nerve-node proxy set 'http://user:password@proxy.example:3128'
nerve-node proxy set http://proxy.example:3128 --header 'X-Proxy-Token: abc'
```

Write special characters of the password as `%XX`. `--header` can be given
more than once.

The values are secrets. The node keeps them in the system keyring (Keychain,
Credential Manager, Secret Service), in one entry named `proxy:<config folder>`
under the service `nerve`. `node.toml` keeps the URL without the login and the
header names. The values never reach a file, the audit log, a log line or an
error. `proxy ls` prints header names only.

A user name and password in the URL become a `Proxy-Authorization: Basic`
header. Do not give that header yourself in the same call.

## Environment variables

Without `proxy set`, the node uses `HTTPS_PROXY` and `NO_PROXY`. A user name or
password in `HTTPS_PROXY` is refused. Use `proxy set` for those.

## When the proxy fails

The node does not fall back to a direct connection. If the proxy is down, the
link stays down. If a keyring entry is missing or unreadable, the link stays
down and `nerve-node status` shows `bad proxy:` with the reason.

On a Linux machine with no Secret Service (no desktop session), `proxy set`
with a header or a password refuses and changes nothing. A proxy without
either works there.

A `node.toml` that holds header values or a login in the file is refused when
it loads. Take the values out of the file, run `nerve-node config accept`,
then run `proxy set` again.
