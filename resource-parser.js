/**
 * 圈X JS 脚本：远程规则转换（只输出规则，不带 [Rule]）
 * 使用方式：在圈X脚本添加，脚本参数填远程规则 URL
 */

let url = $argument[0]; // 第一个参数：远程规则 URL

function getName(domain) {
    if(!domain) return '';
    domain = domain.replace(/^\.+|\*+/g, ''); // 去掉开头的 . 或 *
    let parts = domain.split('.');
    if(parts.length >= 2) return parts[parts.length-2]; // 取倒数第二段作为名字
    return parts[0];
}

if(!url){
    $done('# 请提供远程规则 URL');
} else {
    $httpClient.get(url, (error, response, data) => {
        if(error || response.status !== 200){
            $done('# 下载规则失败: ' + (error || response.status));
            return;
        }

        let lines = data.split(/\r?\n/);
        let output = [];

        lines.forEach(line => {
            line = line.trim();
            if(!line || line.startsWith('#') || line.toUpperCase() === '[RULE]') return;

            let domain = '';
            let type = '';
            let name = '';

            if(/^HOST(-SUFFIX|-WILDCARD|-KEYWORD)?[,]/i.test(line)){
                let parts = line.split(',');
                type = parts[0].toUpperCase();
                domain = parts[1];
                name = getName(domain);
                output.push(`${type},${domain},${name}`);
            }
            else if(/^(USER-AGENT|GEOIP|IP-ASN|IP-CIDR|IP6-CIDR)[,]/i.test(line)){
                let parts = line.split(',');
                type = parts[0].toUpperCase();
                domain = parts[1];
                name = type;
                output.push(`${type},${domain},${name}`);
            }
            else if(/^DOMAIN[,]/i.test(line)){
                domain = line.split(',')[1];
                if(!domain) return;
                name = getName(domain);

                if(domain.includes('*')){
                    type = 'HOST-WILDCARD';
                } else if(domain.startsWith('.')){
                    type = 'HOST-SUFFIX';
                    domain = domain.slice(1);
                } else {
                    type = 'HOST';
                }

                output.push(`${type},${domain},${name}`);
            }
            else if(/^DOMAIN-SUFFIX[,]/i.test(line)){
                domain = line.split(',')[1];
                if(!domain) return;
                type = 'HOST-SUFFIX';
                name = getName(domain);
                output.push(`${type},${domain},${name}`);
            }
            else if(/^DOMAIN-KEYWORD[,]/i.test(line)){
                domain = line.split(',')[1];
                if(!domain) return;
                type = 'HOST-KEYWORD';
                name = getName(domain);
                output.push(`${type},${domain},${name}`);
            }
        });

        $done(output.join('\n'));
    });
}
