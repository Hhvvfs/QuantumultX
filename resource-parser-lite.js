/**
 * Quantumult X 资源解析器
 * 功能：
 * 1. 抓取小火箭/远程规则集节点
 * 2. 自动解析节点（V2Ray/SS/Trojan）
 * 3. 解析规则并转换为 QX 格式
 */

const inputURL = "https://example.com/remote-rules.txt"; // 远程规则/节点 URL
const defaultProxyName = "Proxy"; // 转换后默认节点名称

$task.fetch(inputURL).then(response => {
    const raw = response.body;
    const lines = raw.split(/\r?\n/).map(l => l.trim()).filter(Boolean);

    let nodeList = [];
    let ruleList = [];

    lines.forEach(line => {
        // 判断是否是节点（Vmess/SS/Trojan）
        if (line.startsWith('vmess://') || line.startsWith('ss://') || line.startsWith('trojan://')) {
            nodeList.push(line);
        } else {
            // 解析规则
            const parts = line.split(',');
            const type = parts[0].toUpperCase();
            const value = parts[1];

            switch (type) {
                case 'DOMAIN-SUFFIX':
                    ruleList.push(`DOMAIN-SUFFIX,${value},${defaultProxyName}`);
                    break;
                case 'DOMAIN':
                    ruleList.push(`DOMAIN,${value},${defaultProxyName}`);
                    break;
                case 'IP-CIDR':
                    ruleList.push(`IP-CIDR,${value},${defaultProxyName}`);
                    break;
                case 'GEOIP':
                    ruleList.push(`GEOIP,${value},${defaultProxyName}`);
                    break;
                case 'FINAL':
                    ruleList.push(`FINAL,DIRECT`);
                    break;
                default:
                    break;
            }
        }
    });

    // 输出结果
    const output = [
        '# 节点列表',
        ...nodeList,
        '\n# 规则列表',
        ...ruleList
    ].join('\n');

    $done({ body: output });
}).catch(err => {
    $done({ body: `解析失败: ${err}` });
});
