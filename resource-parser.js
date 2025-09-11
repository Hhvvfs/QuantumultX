/**
 * 圈X JS 脚本：远程规则转换（过滤不支持规则 + DOMAIN映射）
 * 使用方式：在圈X脚本添加，脚本参数填远程规则 URL
 */

let url = $argument[0]; // 第一个参数：远程规则 URL

if (!url) {
    $done('[Rule]\n# 请提供远程规则 URL');
} else {
    $httpClient.get(url, (error, response, data) => {
        if (error || response.status !== 200) {
            $done('[Rule]\n# 下载规则失败: ' + (error || response.status));
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
            // 2️⃣ USER-AGENT / GEOIP / IP-ASN / IP-CIDR / IP6-CIDR
            else if (/^(USER-AGENT|GEOIP|IP-ASN|IP-CIDR|IP6-CIDR)[,]/i.test(line)) {
                let parts = line.split(',');
                output.push(`${parts[0].toUpperCase()},${parts[1]}`);
            }
            // 3️⃣ DOMAIN 系列 → HOST 系列
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
                if (domain) output.push(`HOST-SUFFIX,${domain}`);
            }
            else if (/^DOMAIN-KEYWORD[,]/i.test(line)) {
                let domain = line.split(',')[1];
                if (domain) output.push(`HOST-KEYWORD,${domain}`);
            }
            // 其他不支持规则直接忽略
        });

        $done('[Rule]\n' + output.join('\n'));
    });
}
