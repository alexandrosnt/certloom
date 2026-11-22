# Writing a DNS plugin

certloom-agent has two built-in DNS-01 providers, `rfc2136` and `cloudflare`. Every other
DNS service is supported through a plugin: an executable on the agent host that adds and
removes TXT records when the agent asks. Plugins can be written in any language. The design
is recorded in [ADR-0017](adr/0017-dns01.md).

A plugin only writes records. The agent follows CNAMEs, waits for the record to be visible
and talks to the CA, so a plugin cannot weaken validation.

## Protocol (version 1)

The agent runs the plugin directly (no shell) with one argument, `describe`, `present` or
`cleanup`, and writes one JSON object to its stdin:

```json
{
  "protocol": 1,
  "fqdn": "_acme-challenge.www.example.com.",
  "value": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0",
  "zone": "example.com.",
  "config": {"endpoint": "https://dns-api.internal"},
  "domain": "www.example.com",
  "token": "...",
  "key_auth": "..."
}
```

- `fqdn` is the record to write, after CNAME resolution, with a trailing dot.
- `value` is the TXT record's content.
- `zone` is the solver zone that matched `fqdn`.
- `config` is the solver's `config` map from the agent config, unchanged. It holds no secrets.
- `domain`, `token` and `key_auth` are the ACME values that `fqdn` and `value` come from. They
  are only needed by plugins that wrap a client which derives the record itself.
- `secrets` is present only for a central solver with a stored credential (ADR-0018): the
  object that was stored in certloom, delivered for this call only. Never log it.

The plugin writes one JSON object to stdout:

| Case | Response |
|---|---|
| `describe` | `{"ok":true,"protocol":1,"name":"example","version":"1.2.0","kinds":["dns_solver"]}` |
| success | `{"ok":true}` |
| failure | `{"error":"token rejected","class":"auth"}` |
| rate limited | `{"error":"slow down","class":"rate_limited","retry_after":30}` |

Error classes are `auth`, `rate_limited`, `transient` and `permanent`. A non-zero exit
without a valid response counts as `transient`. Stdout is limited to 64 KiB, and stderr is
copied to the agent log.

## Rules

- `present` and `cleanup` must be idempotent. Presenting an existing value succeeds, and
  removing a missing one succeeds.
- Only touch the given value. A wildcard and its apex share one record name with two
  values.
- Host-configured plugins read their own credentials from a file, their environment, or
  instance identity. Central plugins get them in `secrets`, or use instance identity when
  the solver is `ambient`.
  The agent starts plugins with only `PATH` plus the variables listed in the solver's `env`.
- Finish within the solver's `timeout_seconds` (default 60).

## Installing

A DNS plugin can be installed as a signed package with `certloom-plugin` and named in
`plugin:` (`plugin: corp-dns`), like any other plugin; see [plugins.md](plugins.md).

Or install the executable root-owned and not writable by group or others, then pin its
digest:

```yaml
dns_solvers:
  - name: example
    plugin: /usr/libexec/certloom/dns/certloom-dns-example
    sha256: <output of sha256sum>
    zones: [example.net]
    config: {endpoint: "https://dns-api.internal"}
    env: [EXAMPLE_DNS_TOKEN]
```

The agent refuses the plugin if the file's digest no longer matches. After an upgrade,
update the pin.

## Testing

```sh
certloom-agent dns-test --config /etc/certloom-agent/config.yaml --solver example --name www.example.net
```

This runs `describe`, presents a random value twice, waits until the record resolves,
cleans up twice and waits until the record is gone. Every step is reported as PASS or FAIL.

## Go

Plugins written in Go can use `github.com/alexandrosnt/certloom/plugin` (a `plugin.Server`
with `DNS` set) or the older `github.com/alexandrosnt/certloom/dnsplugin`, which wraps it:
implement `Handler` and call `dnsplugin.Serve` from `main` (see the package example).
