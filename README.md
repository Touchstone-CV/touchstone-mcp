# touchstone-mcp

Local [MCP](https://modelcontextprotocol.io) server for **[Touchstone](https://touchstone.cv)** — record what your
agent did into a tamper-evident, externally-anchored log.

This server runs on **your** machine and holds **your** Ed25519 signing key. It signs each
event locally and appends it to your recorder, so an agent only has to call
`touchstone_record({ event_type, payload })`. **The key never leaves this process.**
Canonicalization (JCS / RFC 8785) is done locally too, so a malicious or compromised server
can't trick you into signing a different commitment than you intended.

Zero dependencies — Node 18+ built-ins only. It's a single file: read it before you trust it.

> The remote MCP at `https://touchstone.cv/mcp` can't sign for you (Touchstone never holds your
> key), so its `touchstone_record` expects a signature you computed yourself. Run **this** server
> when you want frictionless local signing.

## Install

```bash
# one-off, no install:
npx -y @touchstone-cv/mcp

# or vendor the single file:
curl -O https://touchstone.cv/touchstone-mcp.mjs

# or clone:
git clone https://github.com/Touchstone-CV/touchstone-mcp && cd touchstone-mcp
```

## Configure

Point your MCP client at it over stdio:

```json
{
  "mcpServers": {
    "touchstone": {
      "command": "npx",
      "args": ["-y", "@touchstone-cv/mcp"],
      "env": {
        "TOUCHSTONE_RECORDER": "rec_...",
        "TOUCHSTONE_SUBJECT": "<your-colony-sub>",
        "TOUCHSTONE_API_KEY": "tsk_...",
        "TOUCHSTONE_SIGNING_KEY": "<base64 Ed25519 32-byte seed>"
      }
    }
  }
}
```

| Env var | Required | Meaning |
|---|---|---|
| `TOUCHSTONE_RECORDER` | yes | Your recorder public id (`rec_…`) |
| `TOUCHSTONE_SUBJECT` | to record | Your Colony `sub` — the recorder's subject |
| `TOUCHSTONE_API_KEY` | yes | API key minted on the recorder (`tsk_…`) |
| `TOUCHSTONE_SIGNING_KEY` | to record | base64 Ed25519 32-byte seed — **kept by you, never sent** |
| `TOUCHSTONE_KEY_FILE` | alt | Path to JSON `{"seed_b64":"…"}` instead of the inline seed |
| `TOUCHSTONE_BASE_URL` | no | Defaults to `https://touchstone.cv` |

To get a recorder + key, see **[touchstone.cv/developers](https://touchstone.cv/developers)** — agents can
self-provision one with their own Colony token (OAuth Token Exchange, RFC 8693), no browser required.

## Tools

| Tool | What it does |
|---|---|
| `touchstone_record` | JCS-canonicalizes `payload`, signs the commitment **locally**, appends the entry |
| `touchstone_disclose` | Create a shareable `/d/<token>` disclosure link (proxies to the service) |
| `touchstone_verify` | Verify a disclosure bundle (proxies to the service) |
| `touchstone_recorder_info` | Fetch your recorder's public info / checkpoint state |

Only `touchstone_record` uses your signing key; the rest proxy to the remote service over your API key.

## Verifying the log

A disclosure can be checked by anyone, with no trust in Touchstone — in the
[browser verifier](https://touchstone.cv/verify), the standalone
[`verify.php`](https://touchstone.cv/verify.php), or the
[`gossip_check.py`](https://touchstone.cv/gossip_check.py) split-view checker. Those tools are served
from the site (and are each a single auditable file); this repo is just the recording client.

## License

[Apache-2.0](./LICENSE).
