# verdaccio-depgate

**DepGate** is a [Verdaccio](https://verdaccio.org/) middleware plugin that blocks risky **npm package tarball downloads**.

It supports:

1. A local **blacklist / whitelist** (`policy.json`)
2. Live checks against the [OSV](https://osv.dev/) API for **Critical** issues (severity `CRITICAL` or CVSS ≥ 9.0 by default)

Blocked requests return **HTTP 403** with a clear policy message. Normal packages continue to download as usual.

> This is a generic open-source edition. Configure paths, thresholds, and contact text for your own environment.

---

## How it works

On tarball download (`/:package/-/:file.tgz` and `/@:scope/:package/-/:file.tgz`):

1. **Blacklist** → deny  
2. **Whitelist** (`name@version` or `name@*`) → skip OSV, allow  
3. **OSV** → deny if Critical / high CVSS  
4. Otherwise → allow

| Result | HTTP | Log |
|---|---|---|
| Blacklisted | 403 | `[DepGate] MANUAL BLOCK` |
| OSV Critical | 403 | `[DepGate] OSV BLOCK` |
| Whitelisted | allowed | `[DepGate] WHITELISTED` |
| OSV down (default) | allowed | fail-open warning |

---

## Install

```bash
git clone https://github.com/AbnetM/Verdaccio-DepGate.git
cd Verdaccio-DepGate
npm install
npm run build
```

Or link/copy the built package where your Verdaccio instance can resolve `verdaccio-depgate`.

Requires **Node.js ≥ 18** and Verdaccio **6.x**.

---

## Configure Verdaccio

### `config.yaml`

```yaml
middlewares:
  verdaccio-depgate:
    enabled: true
    # optional overrides:
    policyPath: /etc/verdaccio/policy.json
    failClosedOnOsvError: false
    cvssBlockThreshold: 9.0
    contact: security@example.com
```

| Option | Default | Meaning |
|---|---|---|
| `policyPath` | `./policy.json` (process cwd) | Path to whitelist/blacklist JSON |
| `failClosedOnOsvError` | `false` | If `true`, deny when OSV is unreachable |
| `cvssBlockThreshold` | `9.0` | Minimum score to block |
| `contact` | `your security team` | Shown in 403 messages |

Restart Verdaccio after enabling the middleware.

### `policy.json`

Copy the example and edit:

```bash
cp policy.example.json /etc/verdaccio/policy.json
```

```json
{
  "whitelist": ["jsonwebtoken@8.5.2"],
  "blacklist": ["canvas-confetti", "@scope/bad-pkg@1.0.0"]
}
```

| Pattern | Blacklist | Whitelist |
|---|---|---|
| `name` | all versions | ignored |
| `name@version` | that version | skip OSV for that version |
| `name@*` | all versions | skip OSV for all versions |

---

## Verify

```bash
# expect 403 if blacklisted
curl -i "http://localhost:4873/canvas-confetti/-/canvas-confetti-1.9.3.tgz"

# expect 403 for a known Critical version (example)
curl -i "http://localhost:4873/minimist/-/minimist-0.0.8.tgz"

# expect 200 for a clean package
curl -i "http://localhost:4873/lodash/-/lodash-4.17.21.tgz"
```

```bash
# logs
grep DepGate /path/to/verdaccio.log
```

---

## Development

```bash
npm install
npm run build
```

- Logic: `src/middleware-plugin.ts`
- Types / config: `types/index.ts`

`lib/` is build output and is gitignored.

---

## Security notes

- Default mode **fails open** if OSV is unreachable (blacklist still applies when policy loads).
- OSV needs outbound HTTPS to `https://api.osv.dev`.
- This plugin does not identify the calling application/repo—only the package download request.
- Review whitelist entries carefully; `name@*` skips scanning for every version.

---

## License

MIT
