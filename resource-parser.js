/**
 * Quantumult X 远程规则集解析器
 * 功能：下载远程规则集并映射为 Quantumult X 支持的规则类型
 * 支持类型：HOST, HOST-SUFFIX, HOST-WILDCARD, HOST-KEYWORD, USER-AGENT, IP-CIDR, IP6-CIDR, GEOIP, IP-ASN
 * 参考：https://raw.githubusercontent.com/KOP-XIAO/QuantumultX/master/Scripts/resource-parser.js
 * 作者：基于 KOP-XIAO 的资源解析器修改
 * 日期：2025-09-11
 */

const version = typeof $environment != "undefined" ? Number($environment.version.split("build")[1]) : 0;
const Base64 = new Base64Code();
const RuleTypes = ["HOST", "HOST-SUFFIX", "HOST-WILDCARD", "HOST-KEYWORD", "USER-AGENT", "IP-CIDR", "IP6-CIDR", "GEOIP", "IP-ASN"];
let total = "";
let Perror = 0;

// 参数获取
let [link0, content0] = [$resource.link, $resource.content];
let para = /^(http|https)\:\/\//.test(link0) ? link0 : content0.split("\n")[0];
let para1 = para.includes("#") ? para.split("#")[1] : "";
let subtag = typeof $resource.tag != "undefined" ? $resource.tag : "RuleSet";
let Pin0 = para1.includes("in=") ? para1.split("in=")[1].split("&")[0].split("+").map(decodeURIComponent) : null;
let Pout0 = para1.includes("out=") ? para1.split("out=")[1].split("&")[0].split("+").map(decodeURIComponent) : null;
let Preg = para1.includes("regex=") ? decodeURIComponent(para1.split("regex=")[1].split("&")[0]).replace(/\,/g, ",") : null;
let Pregout = para1.includes("regout=") ? decodeURIComponent(para1.split("regout=")[1].split("&")[0]).replace(/\,/g, ",") : null;
let Ppolicy = para1.includes("policy=") ? decodeURIComponent(para1.split("policy=")[1].split("&")[0]) : "Shawn";
let Pntf0 = para1.includes("ntf=") ? para1.split("ntf=")[1].split("&")[0] : 2;
let Pcdn = para1.includes("cdn=") ? para1.split("cdn=")[1].split("&")[0] : "";
let typeU = para1.includes("type=") ? para1.split("type=")[1].split("&")[0] : "";
let typeQ = $resource.type ? $resource.type : "filter";

// 主函数
function RuleParser() {
  let type0 = Type_Check(content0);
  if (type0 === "Rule" || type0 === "Clash-Provider" || typeU === "rule") {
    try {
      total = ProcessRules(content0);
      $done({ content: total });
    } catch (err) {
      Perror = 1;
      $notify("❌ 解析错误", "⚠️ 请检查链接或反馈问题", err, { "open-url": "https://t.me/Shawn_Parser_Bot" });
      $done({ content: "" });
    }
  } else {
    $notify("❌ 不支持的类型", `检测到类型: ${type0}, 仅支持 Rule/Clash-Provider`, "请检查订阅内容", { "open-url": link0 });
    $done({ content: "" });
  }
}

// 类型检测
function Type_Check(subs) {
  const RuleK = ["host,", "-suffix,", "domain,", "-keyword,", "ip-cidr,", "ip-cidr6,", "geoip,", "user-agent,", "ip-asn"];
  const ClashK = ["payload:"];
  const subi = subs.replace(/ /g, "").toLowerCase();
  if (ClashK.some(item => subi.includes(item))) {
    return "Clash-Provider";
  } else if (RuleK.some(item => subi.includes(item)) || typeU === "rule") {
    return "Rule";
  }
  return "unknown";
}

// 规则处理
function ProcessRules(content) {
  let rules = content.split("\n").map(item => item.trim()).filter(Boolean);
  if (typeQ === "Clash-Provider") {
    rules = ClashRule2QX(content);
  }
  rules = Rule_Handle(rules, Pout0, Pin0);
  if (Preg) {
    rules = rules.map(Regex).filter(Boolean);
    RegCheck(rules, "分流引用", "regex", Preg);
  }
  if (Pregout) {
    rules = rules.map(RegexOut).filter(Boolean);
    RegCheck(rules, "分流引用", "regout", Pregout);
  }
  if (Pcdn) {
    rules = CDN(rules);
  }
  rules = rules.filter((ele, pos) => rules.indexOf(ele) === pos); // 去重
  return rules.join("\n");
}

// Clash 规则转换为 Quantumult X
function ClashRule2QX(content) {
  let yaml = new YAML();
  let parsed = yaml.parse(content);
  let rules = [];
  if (parsed["rules"]) {
    parsed["rules"].forEach(rule => {
      let [type, value, policy] = rule.split(",");
      type = type.trim().toUpperCase();
      value = value.trim();
      policy = policy ? policy.trim() : Ppolicy;
      if (RuleTypes.includes(type)) {
        rules.push(`${type},${value},${policy}`);
      }
    });
  }
  return rules;
}

// 规则筛选
function Rule_Handle(rules, Pout, Pin) {
  return rules.map(rule => {
    let tmp = rule.split(",");
    if (tmp.length < 3) return null; // 无效规则
    let type = tmp[0].trim().toUpperCase();
    if (!RuleTypes.includes(type)) return null; // 不支持的类型
    let value = tmp[1].trim();
    let policy = tmp[2].trim();
    if (Pin && Pin.some(pin => value.includes(pin))) return rule;
    if (Pout && Pout.some(out => value.includes(out))) return null;
    return rule;
  }).filter(Boolean);
}

// 正则筛选
function Regex(rule) {
  return Preg && new RegExp(Preg).test(rule) ? rule : null;
}

function RegexOut(rule) {
  return Pregout && new RegExp(Pregout).test(rule) ? null : rule;
}

// 正则检查
function RegCheck(rules, typen, paraname, regpara) {
  if (rules.length === 0) {
    $notify("‼️ " + typen + "  ➟ " + "⟦" + subtag + "⟧", `⛔️ 筛选正则: ${paraname}=${regpara}`, "⚠️ 筛选后剩余项为 0️⃣", { "open-url": link0 });
  } else if (Pntf0 != 0) {
    $notify("🤖 " + typen + "  ➟ " + "⟦" + subtag + "⟧", `⛔️ 筛选正则: ${paraname}=${regpara}`, `⚠️ 筛选后剩余 ${rules.length} 项\n⨷ ${rules.join("\n⨷ ")}`, { "open-url": link0 });
  }
}

// CDN 处理
function CDN(rules) {
  return rules.map(rule => {
    if (rule.includes("github.com")) {
      return rule.replace("github.com", "fastly.jsdelivr.net/gh");
    }
    return rule;
  });
}

// Base64 解码（来自参考脚本）
function Base64Code() {
  const b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const b64tab = (function(bin) {
    let t = {};
    for (let i = 0, l = bin.length; i < l; i++) t[bin.charAt(i)] = i;
    return t;
  })(b64chars);
  this.decode = function(a) {
    return btou(_atob(a.replace(/[-_]/g, m0 => m0 == '-' ? '+' : '/').replace(/[^A-Za-z0-9\+\/]/g, '')))
      .replace(/&gt;/g, ">").replace(/&lt;/g, "<");
    function _atob(a) {
      return a.replace(/\S{1,4}/g, cccc => {
        let len = cccc.length, padlen = len % 4,
          n = (len > 0 ? b64tab[cccc.charAt(0)] << 18 : 0) |
              (len > 1 ? b64tab[cccc.charAt(1)] << 12 : 0) |
              (len > 2 ? b64tab[cccc.charAt(2)] << 6 : 0) |
              (len > 3 ? b64tab[cccc.charAt(3)] : 0),
          chars = [String.fromCharCode(n >>> 16), String.fromCharCode((n >>> 8) & 0xff), String.fromCharCode(n & 0xff)];
        chars.length -= [0, 0, 2, 1][padlen];
        return chars.join('');
      });
    }
    function btou(b) {
      return b.replace(/[\xC0-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF7][\x80-\xBF]{3}/g, cccc => {
        switch (cccc.length) {
          case 4:
            let cp = ((0x07 & cccc.charCodeAt(0)) << 18) | ((0x3f & cccc.charCodeAt(1)) << 12) |
                     ((0x3f & cccc.charCodeAt(2)) << 6) | (0x3f & cccc.charCodeAt(3)),
              offset = cp - 0x10000;
            return String.fromCharCode((offset >>> 10) + 0xD800) + String.fromCharCode((offset & 0x3FF) + 0xDC00);
          case 3:
            return String.fromCharCode(((0x0f & cccc.charCodeAt(0)) << 12) | ((0x3f & cccc.charCodeAt(1)) << 6) | (0x3f & cccc.charCodeAt(2)));
          default:
            return String.fromCharCode(((0x1f & cccc.charCodeAt(0)) << 6) | (0x3f & cccc.charCodeAt(1)));
        }
      });
    }
  }
}

// YAML 解析（来自参考脚本，精简版）
function YAML() {
  const regex = {
    regLevel: /^([\s\-]+)/,
    invalidLine: /^\-\-\-|^\\.\\.\\.|^\\s*#.*|^\\s*$/,
    trim: /^\s+|\s+$/,
    key_value: /([a-z0-9_-][ a-z0-9_-]*):( .+)/i
  };
  this.parse = function(str) {
    let lines = str.split("\n").map(line => line.replace(regex.trim, ""));
    let result = { rules: [] };
    lines.forEach(line => {
      if (!line.match(regex.invalidLine)) {
        let m = line.match(regex.key_value);
        if (m) {
          result[m[1]] = m[2].trim();
        } else if (line.startsWith("- ")) {
          result.rules.push(line.replace(/^- /, ""));
        }
      }
    });
    return result;
  };
}

// 执行解析
if (typeof $resource !== "undefined") {
  RuleParser();
} else {
  $done({ content: "" });
}
