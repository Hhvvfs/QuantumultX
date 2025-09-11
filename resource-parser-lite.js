/**
 * Quantumult X 规则解析器
 * 功能：将原始规则集转换为 Quantumult X 可识别的规则格式
 */

const inputURL = "https://whatshub.top/rule/Google.list"; // 原始规则集 URL
const defaultProxy = "Proxy"; // 默认策略组名

$task.fetch(inputURL).then(response => {
    const raw = response.body;
    const lines = raw.split(/\r?\n/).map(line => line.trim()).filter(Boolean);

    const convertedRules = lines.map(line => {
        const [type, value] = line.split(',').map(part => part.trim());
        if (!type || !value) return null;

        switch (type.toUpperCase()) {
            case 'DOMAIN-SUFFIX':
                return `DOMAIN-SUFFIX,${value},${defaultProxy}`;
            case 'DOMAIN':
                return `DOMAIN,${value},${defaultProxy}`;
            case 'IP-CIDR':
                return `IP-CIDR,${value},${defaultProxy}`;
            case 'GEOIP':
                return `GEOIP,${value},${defaultProxy}`;
            case 'FINAL':
                return `FINAL,DIRECT`;
            default:
                return null;
        }
    }).filter(Boolean);

    const output = [
        '# 规则列表',
        ...convertedRules
    ].join('\n');

    $done({ body: output });
}).catch(err => {
    $done({ body: `解析失败: ${err.message}` });
});
