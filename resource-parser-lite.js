/**
 * Quantumult X 资源规则格式转换器（独立可用）
 * 将输入规则转换为 QX 可识别的格式
 */

const inputURL = "https://example.com/rules.txt"; // 替换为你的规则文件 URL

$task.fetch(inputURL).then(response => {
    const raw = response.body;
    const lines = raw.split(/\r?\n/).map(l => l.trim()).filter(Boolean);

    const converted = lines.map(line => {
        const [type, value] = line.split(',');
        switch (type.toUpperCase()) {
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

    // 输出转换后的规则
    const output = converted.join('\n');
    $done({body: output});
}).catch(err => {
    $done({body: `错误: ${err}`});
});
