/**
 * Quantumult X 资源解析器
 * 功能：将 Surge/Clash 类型规则转换为 Quantumult X 支持的规则
 * 支持类型：
 * HOST, HOST-SUFFIX, HOST-WILDCARD, HOST-KEYWORD,
 * USER-AGENT, IP-CIDR, IP6-CIDR, GEOIP, IP-ASN
 * 特性：保证每条规则都有策略名，默认填 "ChatGPT"
 */

function main(content, url, type) {
  let lines = content.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#"));
  let results = [];

  for (let line of lines) {
    let parts = line.split(",");
    if (parts.length < 2) continue;

    let ruleType = parts[0].toUpperCase();
    let value = parts[1];
    let policy = parts[2] ? parts[2] : "ChatGPT"; // 没有策略名就补上

    switch (ruleType) {
      case "DOMAIN":
        results.push(`HOST,${value},${policy}`);
        break;
      case "DOMAIN-SUFFIX":
        results.push(`HOST-SUFFIX,${value},${policy}`);
        break;
      case "DOMAIN-KEYWORD":
        results.push(`HOST-KEYWORD,${value},${policy}`);
        break;
      case "IP-CIDR6":
        results.push(`IP6-CIDR,${value},${policy}`);
        break;
      case "HOST":
      case "HOST-SUFFIX":
      case "HOST-WILDCARD":
      case "HOST-KEYWORD":
      case "USER-AGENT":
      case "IP-CIDR":
      case "GEOIP":
      case "IP-ASN":
        results.push(`${ruleType},${value},${policy}`);
        break;
      default:
        // 不支持的类型丢弃
        break;
    }
  }

  return results.join("\n");
}
