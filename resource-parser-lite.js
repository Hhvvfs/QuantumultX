// 规则格式转换器
function convertRulesToQuantumultXFormat(rules) {
  return rules.map(rule => {
    const [type, value] = rule.split(',');
    switch (type) {
      case 'DOMAIN-SUFFIX':
        return `DOMAIN-SUFFIX,${value},Proxy`;
      case 'DOMAIN':
        return `DOMAIN,${value},Proxy`;
      case 'IP-CIDR':
        return `IP-CIDR,${value},Proxy`;
      default:
        return null;
    }
  }).filter(Boolean);
}

// 示例使用
const inputRules = [
  'DOMAIN-SUFFIX,example.com',
  'DOMAIN,example.org',
  'IP-CIDR,192.168.1.0/24'
];

const outputRules = convertRulesToQuantumultXFormat(inputRules);
console.log(outputRules);
