// domain-parser.js
// Quantumult X 域名解析器（专为域名列表转换设计，基于 KOP-XIAO 的 resource-parser.js）
// 专注于将域名列表（如 https://whatshub.top/rule/Google.list）转换为 HOST-SUFFIX 规则或 DOMAIN-SET 格式
// 使用方法：在 [general] 中设置 resource_parser_url = https://your-url/domain-parser.js
// 示例订阅链接：https://whatshub.top/rule/Google.list#policy=Proxy&in=google&out=ads

// Base64 编码/解码工具
function Base64Code() {
  const b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const b64tab = (function(bin) {
    const t = {};
    for (let i = 0, l = bin.length; i < l; i++) t[bin.charAt(i)] = i;
    return t;
  })(b64chars);
  const fromCharCode = String.fromCharCode;

  const cb_utob = function(c) {
    if (c.length < 2) {
      const cc = c.charCodeAt(0);
      return cc < 0x80 ? c
        : cc < 0x800 ? (fromCharCode(0xc0 | (cc >>> 6)) + fromCharCode(0x80 | (cc & 0x3f)))
        : (fromCharCode(0xe0 | ((cc >>> 12) & 0x0f)) + fromCharCode(0x80 | ((cc >>> 6) & 0x3f)) + fromCharCode(0x80 | (cc & 0x3f)));
    } else {
      const cc = 0x10000 + (c.charCodeAt(0) - 0xD800) * 0x400 + (c.charCodeAt(1) - 0xDC00);
      return (fromCharCode(0xf0 | ((cc >>> 18) & 0x07)) + fromCharCode(0x80 | ((cc >>> 12) & 0x3f)) + fromCharCode(0x80 | ((cc >>> 6) & 0x3f)) + fromCharCode(0x80 | (cc & 0x3f)));
    }
  };
  const re_utob = /[\uD800-\uDBFF][\uDC00-\uDFFFF]|[^\x00-\x7F]/g;
  const utob = function(u) { return u.replace(re_utob, cb_utob); };
  const cb_encode = function(ccc) {
    const padlen = [0, 2, 1][ccc.length % 3];
    const ord = ccc.charCodeAt(0) << 16 | ((ccc.length > 1 ? ccc.charCodeAt(1) : 0) << 8) | ((ccc.length > 2 ? ccc.charCodeAt(2) : 0));
    const chars = [
      b64chars.charAt(ord >>> 18),
      b64chars.charAt((ord >>> 12) & 63),
      padlen >= 2 ? '=' : b64chars.charAt((ord >>> 6) & 63),
      padlen >= 1 ? '=' : b64chars.charAt(ord & 63)
    ];
    return chars.join('');
  };
  const btoa = function(b) { return b.replace(/[\s\S]{1,3}/g, cb_encode); };

  this.encode = function(u) {
    return btoa(utob(String(u)));
  };
}

const Base64 = new Base64Code();

// 参数解析
function parseParameters(link) {
  const para = /^(http|https)\:\/\//.test(link) ? link : link.split("\n")[0];
  const para1 = para.includes("#") ? para.split("#")[1] : "";
  const mark0 = para.includes("#");
  return {
    policy: mark0 && para1.includes("policy=") ? decodeURIComponent(para1.split("policy=")[1].split("&")[0]) : "Shawn",
    in: mark0 && para1.includes("in=") ? para1.split("in=")[1].split("&")[0].split("+").map(decodeURIComponent) : null,
    out: mark0 && para1.includes("out=") ? para1.split("out=")[1].split("&")[0].split("+").map(decodeURIComponent) : null,
    b64: mark0 && para1.includes("b64=") ? para1.split("b64=")[1].split("&")[0] : 0, // 是否 Base64 编码输出
    ntf: mark0 && para1.includes("ntf=") ? para1.split("ntf=")[1].split("&")[0] : 1, // 通知开关
    type: mark0 && para1.includes("type=") ? para1.split("type=")[1].split("&")[0] : "domain-set" // 强制类型
  };
}

// 类型检测（仅限域名相关）
function Type_Check(subs) {
  const subi = subs.toLowerCase().replace(/ /g, "");
  const lines = subs.split("\n").filter(Boolean);
  
  // 检查是否为域名列表
  if (lines.length > 0 && lines.every(line => /^[\w\.-]+\.(com|org|net|io|top|google|etc)$/i.test(line.trim()) || line.startsWith("||"))) {
    return "domain-set";
  }
  return "unknown";
}

// 域名列表转换为 HOST-SUFFIX 规则
function Domain2QX(lines, policy) {
  const domains = lines
    .filter(line => line.trim() && !line.startsWith("#") && !line.startsWith("!"))
    .map(line => line.trim().replace(/^(\|\||https?:\/\/)/, "").replace(/\^.*$/, ""))
    .filter(domain => domain.includes(".") && !domain.startsWith("http"));
  
  return domains.map(domain => `HOST-SUFFIX,${domain},${policy}`).join("\n");
}

// 规则过滤
function FilterRules(rules, pin, pout) {
  if (!pin && !pout) return rules;
  return rules.filter(rule => {
    const domain = rule.split(",")[1];
    let keep = true;
    if (pin) keep = pin.some(keyword => domain.includes(keyword));
    if (pout) keep = keep && !pout.some(keyword => domain.includes(keyword));
    return keep;
  });
}

// 主解析函数
function DomainParse() {
  const link0 = $resource.link || "";
  let content0 = $resource.content || "";
  const subtag = $resource.tag || "Domain Set";

  // 检查内容是否有效
  if (!content0 || content0.trim() === "") {
    $notify("❌ 内容为空", `${subtag} 没有获取到有效内容`, "请检查链接", { "open-url": link0 });
    return $done({ content: "" });
  }

  // 参数解析
  const params = parseParameters(link0);
  const { policy, in: Pin0, out: Pout0, b64, ntf, type } = params;
  const showNotify = ntf != 0;

  const detectedType = Type_Check(content0);
  if (showNotify && detectedType !== type && type !== "unknown") {
    $notify("⚠️ 类型不匹配", `检测到 ${detectedType}，但指定 ${type}`, "继续使用指定类型");
  }
  if (type === "unknown") type = detectedType;

  let total = "";
  let ruleCount = 0;

  // 域名转换逻辑
  if (type === "domain-set" || detectedType === "domain-set") {
    let lines = content0.split("\n").filter(Boolean);
    let rules = Domain2QX(lines, policy).split("\n").filter(Boolean);
    if (Pin0 || Pout0) rules = FilterRules(rules, Pin0, Pout0);
    total = rules.join("\n");
    ruleCount = rules.length;

    // Base64 编码为 DOMAIN-SET（Quantumult X 要求）
    if (b64 == 1) {
      const setContent = `#!name=${subtag}\n${total}`;
      total = `data:application/vnd.quantumultx.domain-set;base64,${Base64.encode(setContent)}`;
    } else {
      total = `#!name=${subtag}\n${total}`;
    }
  } else {
    $notify("❌ 未知格式", `不支持 ${detectedType} 或 ${type}`, "请确保链接为域名列表并指定 type=domain-set", { "open-url": link0 });
    return $done({ content: "" });
  }

  if (showNotify && total) {
    $notify("✅ 域名解析成功", `${subtag}: ${ruleCount} 条规则`, `策略: ${policy}`, { "open-url": link0 });
  } else if (showNotify && !total) {
    $notify("⚠️ 解析结果为空", `${subtag} 无有效域名`, "请检查链接或参数", { "open-url": link0 });
  }

  return $done({ content: total });
}

// 主入口
try {
  DomainParse();
} catch (err) {
  $notify("❌ 域名解析失败", "发生错误", String(err), { "open-url": "https://t.me/Shawn_Parser_Bot" });
  $done({ content: "" });
}
