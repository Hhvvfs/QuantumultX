/*
  圈X JS 引擎脚本：远程规则转换
  功能：
  1. 下载远程规则订阅（Surge / Clash / 其他常见规则集）
  2. 只保留圈X支持的类型：
     HOST, HOST-SUFFIX, HOST-WILDCARD, HOST-KEYWORD
     USER-AGENT, IP-CIDR, IP6-CIDR, GEOIP, IP-ASN
  3. 自动映射 DOMAIN 系列规则为 HOST 系列
  4. 输出 [Rule] 可直接导入圈X
*/

let url = $environment.query.url;       // 从 URL 参数获取远程规则订阅地址
let groupName = $environment.query.group || 'Proxy'; // 可指定策略组名称

if(!url) {
  $done({response: {status: 400, body: '请提供订阅 URL: ?url=xxxx'}});
} else {
  $httpClient.get(url, function(error, response, data){
    if(error || response.status !== 200){
      $done({response: {status: 500, body: '下载规则失败: ' + (error || response.status)}});
      return;
    }

    let lines = data.split(/\r?\n/);
    let output = [];

    lines.forEach(line => {
      line = line.trim();
      if(!line || line.startsWith('#')) return;

      // 1️⃣ HOST 系列保留
      if(/^HOST(-SUFFIX|-WILDCARD|-KEYWORD)?[,]/i.test(line)){
        let parts = line.split(',');
        output.push(`${parts[0].toUpperCase()},${parts[1]},${groupName}`);
      }
      // 2️⃣ USER-AGENT / GEOIP / IP-ASN / IP-CIDR 系列保留
      else if(/^(USER-AGENT|GEOIP|IP-ASN|IP-CIDR|IP6-CIDR)[,]/i.test(line)){
        let parts = line.split(',');
        output.push(`${parts[0].toUpperCase()},${parts[1]},${groupName}`);
      }
      // 3️⃣ DOMAIN 系列自动映射成 HOST 系列
      else if(/^DOMAIN,/i.test(line)){
        let domain = line.split(',')[1];
        if(domain.includes('*')) {
          output.push(`HOST-WILDCARD,${domain.replace(/\*/g,'*')},${groupName}`);
        } else if(domain.startsWith('.')) {
          output.push(`HOST-SUFFIX,${domain.slice(1)},${groupName}`);
        } else {
          output.push(`HOST,${domain},${groupName}`);
        }
      }
      // 其他类型忽略
    });

    let body = '[Rule]\n' + output.join('\n');
    $done({response: {status: 200, body: body}});
  });
}
