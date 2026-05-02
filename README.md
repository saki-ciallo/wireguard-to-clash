# WireGuard to Clash Subscription Converter

A Cloudflare Worker that converts WireGuard subscription links into Clash YAML config.

## Features

- Parse `wireguard://` links and generate Clash proxy nodes
- Support multiple links (one per line)
- Fetch Clash template from a URL
- Token-based access control
- Data stored in Cloudflare Workers KV

## Deployment

### 1. Fork this repository
<!--
### 2. Create KV Namespace

Cloudflare Dashboard → Storage & databases → Wokers KV → Create Instance (e.g. `wg-kv`) -->

### 2. Create Worker

Cloudflare Dashboard → Compute → Workers & Pages → Create application → Continue with GitHub → Select the forked repository → Deploy

### 3. Configure Worker Settings

<!--**KV Namespace Bindings** (Workers & Pages (e.g. `wireguard-to-clash`) → Bindings → Add a binding → KV Namespace):

| Variable name | KV namespace |
|---|---|
| `KV` | `wg-kv` |-->

**Environment Variables** (Workers & Pages → Settings → Variables and Secrets → Environment Variables):

| Name | Description |
|---|---|
| `TOKEN` | Access token (required) |
| `LINK` | `wireguard://...` |
| `SUBCONFIG` | Clash template URL (e.g. `https://raw.githubusercontent.com/.../clash.yaml`) |
| `SUBUPTIME` | Option. Update interval in hours (default: 6) |

<!-- > KV Namespace Bindings and Environment Variables are different sections. KV uses `env.KV.get()`, env vars use `env.TOKEN`.

### 4. Add KV Data

In your KV namespace, add entries:

- **Key:** `LINK.txt` — **Value:** WireGuard links, one per line
- **Key:** `SUBCONFIG` — **Value:** Clash template URL (optional if set in env) -->

## WireGuard Link Format

```
wireguard://PRIVATEKEY@SERVER:PORT?publickey=PUBLICKEY&address=IP/CIDR&mtu=MTU#NAME
```

Example:

```
wireguard://abc123=@1.2.3.4:51820?publickey=xyz789=&address=10.0.0.2/32&mtu=1420#my-node
```

## Access

```
https://your-worker.workers.dev/TOKEN
https://your-worker.workers.dev?token=TOKEN
```

Use this URL as a Clash subscription link.

## Output Format

Controlled by `COMPACT_OUTPUT` at the top of the file:

- `false` (default): standard YAML format
- `true`: compact JSON format

## Acknowledgements

- [wireguard-subconverter-worker](https://github.com/juerson/wireguard-subconverter-worker)
- [CF-Workers-SUB](https://github.com/cmliu/CF-Workers-SUB)
- [mihomo_yamls](https://github.com/HenryChiao/mihomo_yamls)

Powered by GLM-5.1
