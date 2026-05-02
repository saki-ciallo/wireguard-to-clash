const DEFAULT_SUBUPTIME = 6;
const COMPACT_OUTPUT = true; // true: 紧凑JSON格式 {"name":"..."}, false: 标准YAML格式

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const accessToken = env.TOKEN || "";
    const requestToken = url.searchParams.get("token") || url.searchParams.get("pwd") || "";
    const isAuthorized = !accessToken || requestToken === accessToken || url.pathname === `/${accessToken}`;
    // https://abc.com/TOKEN
    // https://abc.com?token=TOKEN
    // https://abc.com?pwd=TOKEN


    if (accessToken && !isAuthorized) {
      return new Response("Forbidden", { status: 403 });
    }

    const linkText = (await readTextFromKV(env, "LINK.txt")) || env.LINK || "";
    const subConfigSource = (await readTextFromKV(env, "SUBCONFIG")) || env.SUBCONFIG || "";
    const wireguardLinks = parseWireGuardLinkList(linkText);

    if (!wireguardLinks.length) {
      return new Response("LINK.txt 中没有可用的 wireguard:// 链接", {
        status: 400,
        headers: {
          "Content-Type": "text/plain; charset=utf-8"
        }
      });
    }

    const template = await resolveClashTemplate(subConfigSource);
    if (!template.trim()) {
      return new Response("SUBCONFIG 模板为空，请设置 SUBCONFIG 变量或 KV", {
        status: 400,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }
    const parsedNodes = [];
    const proxyNames = [];
    const usedNames = new Set();

    const sortedLinks = wireguardLinks
      .map((link, index) => ({ link, index, parsed: parseWireGuardLink(link) }))
      .filter((item) => item.parsed)
      .sort((a, b) => compareWireGuardNames(a.parsed.name, b.parsed.name, a.index, b.index));

    for (const item of sortedLinks) {
      const uniqueName = makeUniqueProxyName(item.parsed.name, usedNames, item.index);
      const [proxyName, clashNode] = buildClashNode({ ...item.parsed, name: uniqueName });

      if (proxyName && clashNode) {
        parsedNodes.push(clashNode);
        proxyNames.push(`      - ${proxyName}`);
      }
    }

    if (!parsedNodes.length) {
      return new Response("没有生成任何 Clash 节点", {
        status: 400,
        headers: {
          "Content-Type": "text/plain; charset=utf-8"
        }
      });
    }

    const clashConfig = injectClashNodesIntoTemplate(template, parsedNodes, proxyNames);

    // 如需开启 base64 混淆输出，取消下方注释并注释掉明文返回部分
    // 不需要开启
    // const base64Data = encodeBase64(clashConfig);
    // return new Response(base64Data, {
    //   status: 200,
    //   headers: {
    //     "Content-Type": "text/plain; charset=utf-8",
    //     "Profile-Update-Interval": `${env.SUBUPTIME || DEFAULT_SUBUPTIME}`,
    //     "Profile-web-page-url": request.url.includes("?") ? request.url.split("?")[0] : request.url
    //   }
    // });

    return new Response(clashConfig, {
      status: 200,
      headers: {
        "Content-Type": "text/yaml; charset=utf-8",
        "Profile-Update-Interval": `${env.SUBUPTIME || DEFAULT_SUBUPTIME}`,
        "Profile-web-page-url": request.url.includes("?") ? request.url.split("?")[0] : request.url
      }
    });
  }
};

async function readTextFromKV(env, key) {
  if (!env || !env.KV) {
    return "";
  }

  try {
    return (await env.KV.get(key)) || "";
  } catch (error) {
    console.error(`读取 KV ${key} 失败:`, error);
    return "";
  }
}

async function resolveClashTemplate(source) {
  const text = (source || "").trim();
  if (!text) {
    return "";
  }

  if (/^https?:\/\//i.test(text)) {
    return await fetchWebPageContent(text);
  }

  return text;
}

async function fetchWebPageContent(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) {
      return "";
    }

    return await response.text();
  } catch (error) {
    console.error(`Failed to fetch ${url}:`, error);
    return "";
  }
}

function parseWireGuardLinkList(text) {
  const raw = (text || "").replace(/^\uFEFF/, "");
  const links = raw
    .split(/\r?\n|\|/)
    .map((item) => item.trim())
    .filter((item) => {
      const lower = item.toLowerCase();
      return lower.startsWith("wireguard://") || lower.startsWith("wg://");
    });

  return [...new Set(links)];
}

function parseWireGuardLink(link) {
  const cleanedLink = (link || "").trim();
  const lowerLink = cleanedLink.toLowerCase();
  const isWireGuard = lowerLink.startsWith("wireguard://");
  const isWg = lowerLink.startsWith("wg://");
  if (!isWireGuard && !isWg) {
    return null;
  }

  try {
    const parsedUrl = new URL(cleanedLink);
    const sp = parsedUrl.searchParams;

    const addressInfo = parseWireGuardAddress(
      decodeSafe(sp.get("address") || sp.get("ip") || "")
    );
    const reserved = parseWireGuardReserved(decodeSafe(sp.get("reserved") || ""));

    let privateKey = decodeSafe(parsedUrl.username || "");
    if (!privateKey) {
      privateKey = decodeSafe(sp.get("privatekey") || sp.get("privateKey") || "");
    }

    const publicKey = decodeSafe(sp.get("publickey") || sp.get("publicKey") || "");
    const presharedKey = decodeSafe(sp.get("presharedkey") || sp.get("presharedKey") || "");
    const flag = decodeSafe(sp.get("flag") || "");

    const rawUdp = sp.get("udp");
    const udp = rawUdp === null ? true : rawUdp === "1" || rawUdp.toLowerCase() === "true";

    let remark = decodeSafe((parsedUrl.hash || "").replace(/^#/, ""));
    if (!remark) {
      remark = flag ? `${flag}-${parsedUrl.hostname}` : `wireguard-${parsedUrl.hostname}:${parsedUrl.port}`;
    }

    return {
      name: remark,
      server: parsedUrl.hostname,
      port: Number(parsedUrl.port || 0),
      privateKey,
      publicKey,
      presharedKey,
      ip: addressInfo.ip,
      ipv6: addressInfo.ipv6,
      mtu: Number(sp.get("mtu") || 1280),
      reserved,
      udp
    };
  } catch (error) {
    let match;
    if (isWireGuard) {
      match = cleanedLink.match(/^wireguard:\/\/([^@]+)@([^/?#]+)(?::(\d+))?\/?\?(.*?)(?:#(.*))?$/i);
    } else {
      match = cleanedLink.match(/^wg:\/\/([^/?#]+)(?::(\d+))?\/?\?(.*?)(?:#(.*))?$/i);
    }
    if (!match) {
      return null;
    }

    const queryIndex = isWireGuard ? 4 : 3;
    const query = new URLSearchParams(match[queryIndex] || "");
    const addressInfo = parseWireGuardAddress(
      decodeSafe(query.get("address") || query.get("ip") || "")
    );

    let privateKey;
    if (isWireGuard) {
      privateKey = decodeSafe(match[1] || "");
    } else {
      privateKey = decodeSafe(query.get("privatekey") || query.get("privateKey") || "");
    }

    const publicKey = decodeSafe(query.get("publickey") || query.get("publicKey") || "");
    const presharedKey = decodeSafe(query.get("presharedkey") || query.get("presharedKey") || "");
    const flag = decodeSafe(query.get("flag") || "");

    const rawUdp = query.get("udp");
    const udp = rawUdp === null ? true : rawUdp === "1" || rawUdp.toLowerCase() === "true";

    const serverIndex = isWireGuard ? 2 : 1;
    const portIndex = isWireGuard ? 3 : 2;
    const hashIndex = isWireGuard ? 5 : 4;

    let remark = decodeSafe(match[hashIndex] || "");
    if (!remark) {
      remark = flag ? `${flag}-${match[serverIndex]}` : `wireguard-${match[serverIndex]}:${match[portIndex] || 0}`;
    }

    return {
      name: remark,
      server: match[serverIndex],
      port: Number(match[portIndex] || 0),
      privateKey,
      publicKey,
      presharedKey,
      ip: addressInfo.ip,
      ipv6: addressInfo.ipv6,
      mtu: Number(query.get("mtu") || 1280),
      reserved: parseWireGuardReserved(decodeSafe(query.get("reserved") || "")),
      udp
    };
  }
}

function parseWireGuardAddress(address) {
  const parts = (address || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

  return {
    ip: parts[0] ? parts[0].replace(/\/.*/, "") : "",
    ipv6: parts[1] ? parts[1].replace(/\/.*/, "") : ""
  };
}

function parseWireGuardReserved(reserved) {
  return (reserved || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => Number(item))
    .filter((item) => Number.isFinite(item));
}

function decodeSafe(text) {
  try {
    return decodeURIComponent(text);
  } catch (error) {
    return text;
  }
}

function makeUniqueProxyName(name, usedNames, index) {
  const baseName = (name || "").trim() || `wireguard-${index + 1}`;
  let uniqueName = baseName;
  let suffix = 2;

  while (usedNames.has(uniqueName)) {
    uniqueName = `${baseName}-${suffix}`;
    suffix += 1;
  }

  usedNames.add(uniqueName);
  return uniqueName;
}

function compareWireGuardNames(a, b, indexA, indexB) {
  const keyA = getWireGuardSortKey(a, indexA);
  const keyB = getWireGuardSortKey(b, indexB);

  if (keyA.group !== keyB.group) {
    return keyA.group - keyB.group;
  }

  const nameCompare = keyA.prefix.localeCompare(keyB.prefix, "en", {
    numeric: true,
    sensitivity: "base"
  });

  if (nameCompare !== 0) {
    return nameCompare;
  }

  return indexA - indexB;
}

function getWireGuardSortKey(name, index) {
  const text = (name || "").trim() || `wireguard-${index + 1}`;
  const prefixMatch = text.match(/^[A-Za-z0-9]+/);
  const prefix = prefixMatch ? prefixMatch[0] : text;
  const firstChar = prefix.charAt(0);

  let group = 2;
  if (/^[A-Za-z]/.test(firstChar)) {
    group = 0;
  } else if (/^[0-9]/.test(firstChar)) {
    group = 1;
  }

  return { group, prefix: prefix.toLowerCase() };
}

function buildClashNode(wireguard) {
  const name = wireguard.name || `wg-${wireguard.server}:${wireguard.port}`;
  const node = {
    name: `${name}`,
    type: "wireguard",
    server: `${wireguard.server || ""}`,
    port: Number(wireguard.port || 0),
    ip: `${wireguard.ip || ""}`,
    "private-key": `${wireguard.privateKey || ""}`,
    "public-key": `${wireguard.publicKey || ""}`,
    reserved: Array.isArray(wireguard.reserved) && wireguard.reserved.length > 0 ? wireguard.reserved : undefined,
    udp: wireguard.udp !== false,
    "remote-dns-resolve": false,
    mtu: Number(wireguard.mtu || 1280)
  };

  if (wireguard.ipv6) {
    node.ipv6 = `${wireguard.ipv6}`;
  }

  if (wireguard.presharedKey) {
    node["pre-shared-key"] = `${wireguard.presharedKey}`;
  }

  return [name, COMPACT_OUTPUT
    ? `  - ${JSON.stringify(node).replace(/\s+/g, "")}`
    : formatYamlNode(node)
  ];
}

function formatYamlNode(node) {
  const lines = [];
  let first = true;
  for (const [key, value] of Object.entries(node)) {
    if (value === undefined) continue;
    const yamlValue = toYamlValue(value);
    if (first) {
      lines.push(`  - ${key}: ${yamlValue}`);
      first = false;
    } else {
      lines.push(`    ${key}: ${yamlValue}`);
    }
  }
  return lines.join("\n");
}

function toYamlValue(value) {
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (Array.isArray(value)) return `[${value.join(", ")}]`;
  if (typeof value === "string") {
    if (/[:{}[\],&*?|>!%#`@\\]/.test(value) || value === "" || /^\d/.test(value) || value !== value.trim()) {
      return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
    }
    return value;
  }
  return String(value);
}

function injectClashNodesIntoTemplate(template, clashNodes, proxyNames) {
  let config = template || "";

  const lines = config.split(/\r?\n/);
  const proxiesIndex = lines.findIndex((line) => line.trim() === "proxies:");
  const groupsIndex = lines.findIndex((line, index) => index > proxiesIndex && line.trim() === "proxy-groups:");

  if (proxiesIndex !== -1 && groupsIndex !== -1 && groupsIndex > proxiesIndex) {
    config = [
      ...lines.slice(0, proxiesIndex + 1),
      ...clashNodes,
      ...lines.slice(groupsIndex)
    ].join("\n");
  } else {
    config = `${config.trimEnd()}\nproxies:\n${clashNodes.join("\n")}\n`;
  }

  config = config.replace(/^ {6}- 01$/gm, proxyNames.join("\n"));
  return config;
}

function encodeBase64(data) {
  const binary = new TextEncoder().encode(data);
  let base64 = "";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  for (let i = 0; i < binary.length; i += 3) {
    const byte1 = binary[i];
    const byte2 = binary[i + 1] || 0;
    const byte3 = binary[i + 2] || 0;

    base64 += chars[byte1 >> 2];
    base64 += chars[((byte1 & 3) << 4) | (byte2 >> 4)];
    base64 += chars[((byte2 & 15) << 2) | (byte3 >> 6)];
    base64 += chars[byte3 & 63];
  }

  const padding = 3 - (binary.length % 3 || 3);
  return base64.slice(0, base64.length - padding) + "==".slice(0, padding);
}
