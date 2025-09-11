/*
 * Quantumult X 简化资源解析器
 * 功能：
 * 1. 将 Surge/Shadowrocket/Clash 规则 转换为 Quantumult X 规则
 * 2. 节点部分原样 passthrough（后续可扩展 ss/vmess/trojan 解析）
 */

function Parse(conf) {
  const content = conf.body;
  if (!content) return "";

  // ----------- 规则解析 -----------
  if (/(DOMAIN-SUFFIX|DOMAIN-KEYWORD|DOMAIN|IP-CIDR|FINAL|GEOIP)/i.test(content)) {
    const lines = content.split("\n");
    const out = lines.map(line => {
      line = line.trim();
      if (!line || /^#|^;|^\/\//.test(line)) return null;
      const parts = line.split(",");
      if (parts.length < 2) return line;
      const type = parts[0].toUpperCase().trim();
      const val = parts[1].trim();
      const policy = parts[2] ? parts[2].trim() : "";
      switch (type) {
        case "DOMAIN-SUFFIX": return `host-suffix, ${val}, ${policy}`;
        case "DOMAIN":        return `host, ${val}, ${policy}`;
        case "DOMAIN-KEYWORD":return `host-keyword, ${val}, ${policy}`;
        case "IP-CIDR":       return `ip-cidr, ${val}, ${policy}`;
        case "GEOIP":         return `geoip, ${val.toLowerCase()}, ${policy}`;
        case "FINAL":         return `final, ${policy}`;
        default:              return line;
      }
    }).filter(Boolean);
    return out.join("\n");
  }

  // ----------- 节点解析（目前先 passthrough）-----------
  if (/^((ss|vmess|trojan):\/\/|vmess=|shadowsocks=|trojan=)/i.test(content.trim())) {
    return content.trim();
  }

  // 默认原样返回
  return content;
}
