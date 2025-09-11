/**
 * Quantumult X 规则格式转换器
 * 可直接运行在 Node.js 或者 Quantumult X 的 Script 模式中
 */

// 示例输入：多行字符串，每行一个规则，格式可以是 SSR/V2Ray/SS 规则类型
const rawRules = `
DOMAIN-SUFFIX,example.com
DOMAIN,example.org
IP-CIDR,192.168.1.0/24
`;

// 转换函数
function parseRules(rawText) {
  const lines = rawText.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const converted = lines.map(line => {
    const parts = line.split(',');
    const type = parts[0].toUpperCase();
    const value = parts[1];
    switch(type) {
      case 'DOMAIN-SUFFIX':
        return `DOMAIN-SUFFIX,${value},Proxy`;
      case 'DOMAIN':
        return `DOMAIN,${value},Proxy`;
      case 'IP-CIDR':
        return `IP-CIDR,${value},Proxy`;
      case 'GEOIP':
        return `GEOIP,${value},Proxy`;
      case 'FINAL':
        return `FINAL,DIRECT`;
      default:
        return null;
    }
  }).filter(Boolean);
  return converted.join('\n');
}

// 输出结果
const quantumultXRules = parseRules(rawRules);
console.log(quantumultXRules);

// 可选：在 Node.js 中写入文件
// const fs = require('fs');
// fs.writeFileSync('qx_rules.txt', quantumultXRules);
