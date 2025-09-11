/**
 * Quantumult X 资源解析器（自动补齐策略名）
 * - 从资源 URL 提取文件名作为策略名，例如 ChatGPT.list -> ChatGPT
 * - 每条规则都保证带策略名（若原始没有则补上）
 */

function main(content, url, type) {
  content = (content || '').replace(/^\uFEFF/, ''); // 去 BOM

  // 从 URL 提取策略名（默认 Default）
  var defaultPolicy = 'Default';
  try {
    var fname = (url || '').split('/').pop() || '';
    if (fname) defaultPolicy = fname.replace(/\.[^.]*$/, '') || defaultPolicy;
  } catch (e) {}

  var lines = content.replace(/\r\n/g, '\n').split('\n');
  var out = [];

  for (var i = 0; i < lines.length; i++) {
    var line = (lines[i] || '').trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;

    // 拆分
    var parts = line.split(',').map(x => x.trim());
    if (parts.length < 2) continue;

    var ruleType = parts[0].toUpperCase();
    var value = parts[1];
    var policy = parts[2] ? parts[2] : defaultPolicy; // 没有就补默认策略名

    // 映射为 Quantumult X 支持类型
    switch (ruleType) {
      case 'DOMAIN':
        out.push(`HOST,${value},${policy}`);
        break;
      case 'DOMAIN-SUFFIX':
        out.push(`HOST-SUFFIX,${value},${policy}`);
        break;
      case 'DOMAIN-KEYWORD':
        out.push(`HOST-KEYWORD,${value},${policy}`);
        break;
      case 'IP-CIDR6':
        out.push(`IP6-CIDR,${value},${policy}`);
        break;
      case 'HOST':
      case 'HOST-SUFFIX':
      case 'HOST-WILDCARD':
      case 'HOST-KEYWORD':
      case 'USER-AGENT':
      case 'IP-CIDR':
      case 'GEOIP':
      case 'IP-ASN':
        out.push(`${ruleType},${value},${policy}`);
        break;
      default:
        // 不支持的类型跳过
        break;
    }
  }

  return out.join('\n');
}
