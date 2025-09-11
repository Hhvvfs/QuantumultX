/**
 * 圈X JS 脚本：远程规则转换（无策略组，直接输出 [Rule]）
 * 使用方式：在圈X添加脚本，脚本参数填远程规则 URL
 */

let url = $argument[0]; // 第一个参数：远程规则 URL

if(!url){
    $done('[Rule]\n# 请提供远程规则 URL');
} else {
    $httpClient.get(url, (error, response, data) => {
        if(error || response.status !== 200){
            $done('[Rule]\n# 下载规则失败: ' + (error || response.status));
            return;
        }

        let lines = data.split(/\r?\n/);
        let output = [];

        lines.forEach(line=>{
            line = line.trim();
            if(!line || line.startsWith('#')) return;

            // HOST 系列
            if(/^HOST(-SUFFIX|-WILDCARD|-KEYWORD)?[,]/i.test(line)){
                let parts = line.split(',');
                output.push(`${parts[0].toUpperCase()},${parts[1]}`);
            }
            // USER-AGENT / GEOIP / IP-ASN / IP-CIDR / IP6-CIDR
            else if(/^(USER-AGENT|GEOIP|IP-ASN|IP-CIDR|IP6-CIDR)[,]/i.test(line)){
                let parts = line.split(',');
                output.push(`${parts[0].toUpperCase()},${parts[1]}`);
            }
            // DOMAIN 系列 → HOST
            else if(/^DOMAIN[,]/i.test(line)){
                let domain = line.split(',')[1];
                if(!domain) return;
                if(domain.includes('*')){
                    output.push(`HOST-WILDCARD,${domain}`);
                } else if(domain.startsWith('.')){
                    output.push(`HOST-SUFFIX,${domain.slice(1)}`);
                } else {
                    output.push(`HOST,${domain}`);
                }
            }
            // DOMAIN-SUFFIX / DOMAIN-KEYWORD → HOST-SUFFIX / HOST-KEYWORD
            else if(/^DOMAIN-SUFFIX[,]/i.test(line)){
                let domain = line.split(',')[1];
                if(domain) output.push(`HOST-SUFFIX,${domain}`);
            }
            else if(/^DOMAIN-KEYWORD[,]/i.test(line)){
                let domain = line.split(',')[1];
                if(domain) output.push(`HOST-KEYWORD,${domain}`);
            }
        });

        $done('[Rule]\n' + output.join('\n'));
    });
}
