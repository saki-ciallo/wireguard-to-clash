# WireGuard to Clash Subscription Converter

A Cloudflare Worker that converts WireGuard subscription links into Clash YAML config.

## Features

- Parse `wireguard://` and `wg://` links
- Support multiple links (one per line)
- Fetch Clash template from a URL
- Token-based access control
- Optional KV storage or direct env variables

## Deployment

### 1. Fork this repository

### 2. Create Worker

Cloudflare Dashboard → Compute → Workers & Pages → Create application → Continue with GitHub → Select the forked repository → Deploy

### 3. Configure Environment Variables

Workers & Pages → Settings → Variables and Secrets → Environment Variables:

| Name | Required | Description |
|---|---|---|
| `TOKEN` | Yes | Access token |
| `LINK` | Yes | WireGuard links, one per line |
| `SUBCONFIG` | Yes | Clash template URL |
| `SUBUPTIME` | No | Update interval in hours (default: 6) |

## Link Formats

### Format A (Short)

```
wireguard://PRIVATEKEY@SERVER:PORT?publickey=PUBLICKEY&address=IP/CIDR&mtu=MTU#NAME
```

### Format B (Standard)

```
wg://SERVER:PORT?publicKey=PUBLICKEY&privateKey=PRIVATEKEY&presharedKey=KEY&ip=IP&flag=US&udp=1#NAME
```


### Parameters

| Parameter | Format A | Format B | Description |
|---|---|---|---|
| `privateKey` | userinfo | query | Private key |
| `publicKey` | `publickey` | `publicKey` | Public key |
| `presharedKey` | — | `presharedKey` | Pre-shared key |
| `address` / `ip` | `address` | `ip` | Local IP (v4,v6) |
| `mtu` | optional | optional | MTU (default: 1280) |
| `udp` | — | optional | UDP relay, default `true` |
| `flag` | — | optional | Prefix for node name |
| `#NAME` | hash | hash | Node display name |

The `remote-dns-resolve` set to `false` as default.

## Access

```
https://your-worker.workers.dev/TOKEN
https://your-worker.workers.dev?token=TOKEN
```

Use this URL as a Clash subscription link.

## Output Format

Edit `COMPACT_OUTPUT` in `3_worker.js`:

- `false`: standard YAML format
- `true`: compact JSON format

## Acknowledgements

- [wireguard-subconverter-worker](https://github.com/juerson/wireguard-subconverter-worker)
- [CF-Workers-SUB](https://github.com/cmliu/CF-Workers-SUB)
- [mihomo_yamls](https://github.com/HenryChiao/mihomo_yamls)
- [Mihomo_wireguard](https://wiki.metacubex.one/config/proxies/wg/#_2)

Powered by GLM-5.1, Kimi K2.6
