/*
Quantumult X 资源解析器
作用：把不支持的规则类型转换成 Quantumult X 可识别的类型
*/

function parseResource(content) {
  let lines = content.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#"));
  let results = [];

  for (let line of lines) {
    // Surge/Clash 格式: TYPE,VALUE
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
      case "HOST":
      case "HOST-SUFFIX":
      case "HOST-WILDCARD":
      case "HOST-KEYWORD":
      case "USER-AGENT":
      case "IP-CIDR":
      case "IP-CIDR6":
      case "GEOIP":
      case "IP-ASN":
        results.push(line.replace("IP-CIDR6", "IP6-CIDR")); // 统一一下 IPv6
        break;
      default:
        // Quantumult X 不支持的类型就跳过
        break;
    }
  }

  return results.join("\n");
}

function main(content) {
  return parseResource(content);
}
