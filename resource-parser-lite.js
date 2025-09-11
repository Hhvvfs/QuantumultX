/**
 * Quantumult X 分流规则解析器（可直接抓取远程规则）
 * 用途：将小火箭/远程规则集转换成 QX 可识别规则
 */

const REMOTE_URL = "https://whatshub.top/rule/Google.list"; // 远程规则集 URL
const DEFAULT_PROXY = "Proxy"; // 默认策略组名

$task.fetch(REMOTE_URL).then(response => {
    const raw = response.body;

    // 按行分割，并过滤掉空行和注释
    const lines = raw.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));

    const rules = [];

    lines.forEach(line => {
        let type, value;

        // 检查常见分隔符
        if (line.includes(',')) {
            [type, value] = line.split(',').map(s => s.trim());
        } else if (line.includes('|')) {
            [type, value] = line.split('|').map(s => s.trim());
        } else {
            // 如果行只有一个值，默认为 DOMAIN-SUFFIX
            type = 'DOMAIN-SUFFIX';
            value = line;
        }

        if (!type || !value) return;

        switch (type.toUpperCase()) {
            case 'DOMAIN-SUFFIX':
            case 'DOMAIN':
            case 'IP-CIDR':
            case 'GEOIP':
                rules.push(`${type.toUpperCase()},${value},${DEFAULT_PROXY}`);
                break;
            case 'FINAL':
                rules.push(`FINAL,DIRECT`);
                break;
            default:
                // 忽略未知类型
                break;
        }
    });

    const output = rules.join('\n');
    $done({ body: output });

}).catch(err => {
    $done({ body: `解析失败: ${err.message}` });
});
