// resource-parser.js 通用版
// 读取远程订阅列表并生成圈X规则

const subscriptionsUrl = "https://your-server.com/subscriptions.json"; // 订阅列表文件

async function fetchJson(url) {
    try {
        const resp = await $httpClient.get(url);
        return JSON.parse(resp.body);
    } catch (e) {
        console.log("抓取订阅列表失败:", e);
        return [];
    }
}

async function fetchRules(sub) {
    try {
        const resp = await $httpClient.get(sub.url);
        if (!resp || !resp.body) return [];

        const lines = resp.body.split(/\r?\n/);
        const result = [];

        const typeMap = {
            "DOMAIN-KEYWORD": "HOST-KEYWORD",
            "IP-CIDR": "IP-CIDR",
            "USER-AGENT": "USER-AGENT"
        };

        for (const line of lines) {
            const trimLine = line.trim();
            if (!trimLine || trimLine.startsWith("#")) continue;
            const parts = trimLine.split(",");
            const ruleType = parts[0].trim();
            if (!typeMap[ruleType]) continue;

            let content = parts[1].trim();
            if ((ruleType === "IP-CIDR") && parts[2] && parts[2].trim() === "no-resolve") {
                // 去掉 no-resolve
            }

            result.push(`${typeMap[ruleType]}, ${content}, ${sub.brand}`);
        }
        return result;

    } catch (e) {
        console.log("抓取规则失败:", sub.url, e);
        return [];
    }
}

(async () => {
    const subs = await fetchJson(subscriptionsUrl);
    let allItems = [];

    for (const sub of subs) {
        const rules = await fetchRules(sub);
        allItems = allItems.concat(rules);
    }

    $done({ items: allItems });
})();
