/**
 * 圈X JS 脚本：远程规则集转换（无策略组）
 * 功能：
 * 1. 下载远程规则订阅（Surge / Clash / 其他规则集）
 * 2. 映射 DOMAIN 系列为 HOST 系列（HOST / HOST-SUFFIX / HOST-WILDCARD / HOST-KEYWORD）
 * 3. 保留圈X支持的规则类型：
 *    HOST, HOST-SUFFIX, HOST-WILDCARD, HOST-KEYWORD, USER-AGENT, IP-CIDR, IP6-CIDR, GEOIP, IP-ASN
 * 4. 输出 [Rule] 可直接导入圈X
 */

let url = $argument[0]; // 第一个参数：远程规则 URL

if (!url) {
  $done({ response: { status: 400, body: '请提供远程规则 URL' } });
} else {
  $httpClient.get(url, function (error, response, data) {
    if (error || response.status !== 200) {
      $done({ response: { status: 500, body: '下载规则失败: ' + (error || response.status) } });
      return;
    }

    let lines = data.split(/\r?\n/);
    let output = [];

    lines.forEach(line => {
      line = line.trim();
      if (!line || line.startsWith('#')) return;

      // 1️⃣ HOST 系列直接保留
      if (/^HOST(-SUFFIX|-WILDCARD|-KEYWORD)?[,]/i.test(line)) {
        let parts = line.split(',');
        output.push(`${parts[0].toUpperCase()},${parts[1]}`);
      }
      // 2️⃣ USER-AGENT / GEOIP / IP-ASN / IP-CIDR / IP6-CIDR 系列
      else if (/^(USER-AGENT|GEOIP|IP-ASN|IP-CIDR|IP6-CIDR)[,]/i.test(line)) {
        let parts = line.split(',');
        output.push(`${parts[0].toUpperCase()},${parts[1]}`);
      }
      // 3️⃣ DOMAIN 系列自动映射为 HOST 系列
      else if (/^DOMAIN[,]/i.test(line)) {
        let domain = line.split(',')[1];
        if (!domain) return;

        if (domain.includes('*')) {
          output.push(`HOST-WILDCARD,${domain}`);
        } else if (domain.startsWith('.')) {
          output.push(`HOST-SUFFIX,${domain.slice(1)}`);
        } else {
          output.push(`HOST,${domain}`);
        }
      }
      // 4️⃣ DOMAIN-SUFFIX / DOMAIN-KEYWORD 映射
      else if (/^DOMAIN-SUFFIX[,]/i.test(line)) {
        let domain = line.split(',')[1];
        if (!domain) return;
        output.push(`HOST-SUFFIX,${domain}`);
      }
      else if (/^DOMAIN-KEYWORD[,]/i.test(line)) {
        let domain = line.split(',')[1];
        if (!domain) return;
        output.push(`HOST-KEYWORD,${domain}`);
      }
      // 其他类型忽略
    });

    let body = '[Rule]\n' + output.join('\n');
    $done({ response: { status: 200, body: body } });
  });
}
