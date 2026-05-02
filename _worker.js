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

    for (let index = 0; index < wireguardLinks.length; index++) {
      const parsedLink = parseWireGuardLink(wireguardLinks[index]);
      if (!parsedLink) {
        continue;
      }

      const uniqueName = makeUniqueProxyName(parsedLink.name, usedNames, index);
      const [proxyName, clashNode] = buildClashNode({ ...parsedLink, name: uniqueName });

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
    .filter((item) => item.toLowerCase().startsWith("wireguard://"));

  return [...new Set(links)];
}

function parseWireGuardLink(link) {
  const cleanedLink = (link || "").trim();
  if (!cleanedLink.toLowerCase().startsWith("wireguard://")) {
    return null;
  }

  try {
    const parsedUrl = new URL(cleanedLink);
    const addressInfo = parseWireGuardAddress(decodeSafe(parsedUrl.searchParams.get("address") || ""));
    const reserved = parseWireGuardReserved(decodeSafe(parsedUrl.searchParams.get("reserved") || ""));
    const privateKey = decodeSafe(parsedUrl.username || "");
    const publicKey = decodeSafe(parsedUrl.searchParams.get("publickey") || parsedUrl.searchParams.get("publicKey") || "");
    const remark = decodeSafe((parsedUrl.hash || "").replace(/^#/, "")) || `wireguard-${parsedUrl.hostname}:${parsedUrl.port}`;

    return {
      name: remark,
      server: parsedUrl.hostname,
      port: Number(parsedUrl.port || 0),
      privateKey,
      publicKey,
      ip: addressInfo.ip,
      ipv6: addressInfo.ipv6,
      mtu: Number(parsedUrl.searchParams.get("mtu") || 1280),
      reserved
    };
  } catch (error) {
    const match = cleanedLink.match(/^wireguard:\/\/([^@]+)@([^/?#]+)(?::(\d+))?\/?\?(.*?)(?:#(.*))?$/i);
    if (!match) {
      return null;
    }

    const query = new URLSearchParams(match[4] || "");
    const addressInfo = parseWireGuardAddress(decodeSafe(query.get("address") || ""));

    return {
      name: decodeSafe(match[5] || "") || `wireguard-${match[2]}:${match[3] || 0}`,
      server: match[2],
      port: Number(match[3] || 0),
      privateKey: decodeSafe(match[1] || ""),
      publicKey: decodeSafe(query.get("publickey") || query.get("publicKey") || ""),
      ip: addressInfo.ip,
      ipv6: addressInfo.ipv6,
      mtu: Number(query.get("mtu") || 1280),
      reserved: parseWireGuardReserved(decodeSafe(query.get("reserved") || ""))
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
    udp: true,
    "remote-dns-resolve": false,
    mtu: Number(wireguard.mtu || 1280)
  };

  if (wireguard.ipv6) {
    node.ipv6 = `${wireguard.ipv6}`;
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
