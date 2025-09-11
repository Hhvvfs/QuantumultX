/**
 * Quantumult X 资源解析器
 * 功能：将 Surge/Clash 类型规则转换为 Quantumult X 支持的规则
 * 支持类型：
 * HOST, HOST-SUFFIX, HOST-WILDCARD, HOST-KEYWORD,
 * USER-AGENT, IP-CIDR, IP6-CIDR, GEOIP, IP-ASN
 */

function parseResource(content) {
  let lines = content.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#"));
  let results = [];

  for (let line of lines) {
    let parts = line.split(",");
    if (parts.length < 2) continue;
    let type = parts[0].toUpperCase();
    let value = parts[1];

    switch (type) {
      case "DOMAIN":
        results.push(`HOST,${value}`);
        break;
      case "DOMAIN-SUFFIX":
        results.push(`HOST-SUFFIX,${value}`);
        break;
      case "DOMAIN-KEYWORD":
        results.push(`HOST-KEYWORD,${value}`);
        break;
      case "IP-CIDR6":
        results.push(`IP6-CIDR,${value}`);
        break;
      case "HOST":
      case "HOST-SUFFIX":
      case "HOST-WILDCARD":
      case "HOST-KEYWORD":
      case "USER-AGENT":
      case "IP-CIDR":
      case "GEOIP":
      case "IP-ASN":
        results.push(`${type},${value}`);
        break;
      default:
        // Quantumult X 不支持的类型丢弃，比如 PROCESS-NAME, RULE-SET 等
        break;
    }
  }

  return results.join("\n");
}

function main(content) {
  return parseResource(content);
}
