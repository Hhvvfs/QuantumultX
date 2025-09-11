// resource-parser.js
// Quantumult X 资源解析器（精简版，基于 KOP-XIAO 的脚本）
// 专为 Quantumult X 环境设计，支持节点、规则、重写解析
// 使用方法：在订阅链接后加参数，例如：https://example.com/sub#in=香港&out=台湾

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
    const isUint8Array = Object.prototype.toString.call(u) === '[object Uint8Array]';
    return isUint8Array ? u.toString('base64') : btoa(utob(String(u)));
  };

  const re_btou = /[\xC0-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF7][\x80-\xBF]{3}/g;
  const cb_btou = function(cccc) {
    switch (cccc.length) {
      case 4:
        const cp = ((0x07 & cccc.charCodeAt(0)) << 18) | ((0x3f & cccc.charCodeAt(1)) << 12) | ((0x3f & cccc.charCodeAt(2)) << 6) | (0x3f & cccc.charCodeAt(3));
        const offset = cp - 0x10000;
        return (fromCharCode((offset >>> 10) + 0xD800) + fromCharCode((offset & 0x3FF) + 0xDC00));
      case 3:
        return fromCharCode(((0x0f & cccc.charCodeAt(0)) << 12) | ((0x3f & cccc.charCodeAt(1)) << 6) | (0x3f & cccc.charCodeAt(2)));
      default:
        return fromCharCode(((0x1f & cccc.charCodeAt(0)) << 6) | (0x3f & cccc.charCodeAt(1)));
    }
  };
  const btou = function(b) { return b.replace(re_btou, cb_btou); };
  const cb_decode = function(cccc) {
    const len = cccc.length;
    const padlen = len % 4;
    const n = (len > 0 ? b64tab[cccc.charAt(0)] << 18 : 0) | (len > 1 ? b64tab[cccc.charAt(1)] << 12 : 0) | (len > 2 ? b64tab[cccc.charAt(2)] << 6 : 0) | (len > 3 ? b64tab[cccc.charAt(3)] : 0);
    const chars = [fromCharCode(n >>> 16), fromCharCode((n >>> 8) & 0xff), fromCharCode(n & 0xff)];
    chars.length -= [0, 0, 2, 1][padlen];
    return chars.join('');
  };
  const atob = function(a) { return cb_decode(String(a).replace(/[^A-Za-z0-9\+\/]/g, '')); };

  this.decode = function(a) {
    return btou(atob(a.replace(/[-_]/g, function(m0) { return m0 == '-' ? '+' : '/'; }).replace(/[^A-Za-z0-9\+\/]/g, ''))).replace(/&gt;/g, '>').replace(/&lt;/g, '<');
  };
}

const Base64 = new Base64Code();

// YAML 解析器（精简版）
function YAMLParser() {
  const regex = {
    regLevel: new RegExp("^([\\s\\-]+)"),
    invalidLine: new RegExp("^\\-\\-\\-|^\\.\\.\\.|^\\s*#.*|^\\s*$"),
    dashesString: new RegExp("^\\s*\\\"([^\\\"]*)\\\"\\s*$"),
    quotesString: new RegExp("^\\s*\\\'([^\\\']*)\\\'\\s*$"),
    float: new RegExp("^[+-]?[0-9]+\\.[0-9]+(e[+-]?[0-9]+(\\.[0-9]+)?)?$"),
    integer: new RegExp("^[+-]?[0-9]+$"),
    array: new RegExp("\\[\\s*(.*)\\s*\\]"),
    map: new RegExp("\\{\\s*(.*)\\s*\\}"),
    key_value: new RegExp("([a-z0-9_-][ a-z0-9_-]*):( .+)", "i"),
    single_key_value: new RegExp("^([a-z0-9_-][ a-z0-9_-]*):( .+?)$", "i"),
    key: new RegExp("([a-z0-9_-][ a-z0-9_-]+):( .+)?", "i"),
    item: new RegExp("^-\\s+"),
    trim: new RegExp("^\\s+|\\s+$"),
    comment: new RegExp("([^\\\'\\\"#]+([\\\'\\\"][^\\\'\\\"]*[\\\'\\\"])*)*(#.*)?")
  };

  function Block(lvl) {
    return {
      parent: null,
      length: 0,
      level: lvl,
      lines: [],
      children: [],
      addChild: function(obj) {
        this.children.push(obj);
        obj.parent = this;
        ++this.length;
      }
    };
  }

  function parser(str) {
    const lines = str.split("\n");
    let level = 0, curLevel = 0;
    const blocks = [];
    const result = new Block(-1);
    let currentBlock = new Block(0);
    result.addChild(currentBlock);
    const levels = [];
    blocks.push(currentBlock);
    levels.push(level);

    for (let i = 0, len = lines.length; i < len; ++i) {
      const line = lines[i];
      if (line.match(regex.invalidLine)) continue;
      const m = regex.regLevel.exec(line);
      level = m ? m[1].length : 0;

      if (level > curLevel) {
        const oldBlock = currentBlock;
        currentBlock = new Block(level);
        oldBlock.addChild(currentBlock);
        blocks.push(currentBlock);
        levels.push(level);
      } else if (level < curLevel) {
        let added = false;
        let k = levels.length - 1;
        for (; k >= 0; --k) {
          if (levels[k] == level) {
            currentBlock = new Block(level);
            blocks.push(currentBlock);
            levels.push(level);
            if (blocks[k].parent != null) blocks[k].parent.addChild(currentBlock);
            added = true;
            break;
          }
        }
        if (!added) throw new Error("Invalid indentation at line " + i + ": " + line);
      }

      currentBlock.lines.push(line.replace(regex.trim, ""));
      curLevel = level;
    }
    return result;
  }

  function processValue(val) {
    val = val.replace(regex.trim, "");
    if (val == 'true') return true;
    if (val == 'false') return false;
    if (val == '.NaN') return Number.NaN;
    if (val == 'null') return null;
    if (val == '.inf') return Number.POSITIVE_INFINITY;
    if (val == '-.inf') return Number.NEGATIVE_INFINITY;

    let m = val.match(regex.dashesString);
    if (m) return m[1];
    m = val.match(regex.quotesString);
    if (m) return m[1];
    m = val.match(regex.float);
    if (m) return parseFloat(m[0]);
    m = val.match(regex.integer);
    if (m) return parseInt(m[0]);
    if (!isNaN(m = Date.parse(val))) return new Date(m);

    m = val.match(regex.array);
    if (m) {
      let res = [], content = "", str = false, count = 0;
      for (let j = 0, lenJ = m[1].length; j < lenJ; ++j) {
        const c = m[1][j];
        if (c == '\'' || c == '"') {
          if (str === false) {
            str = c;
            content += c;
            continue;
          } else if ((c == '\'' && str == '\'') || (c == '"' && str == '"')) {
            str = false;
            content += c;
            continue;
          }
        } else if (str === false && (c == '[' || c == '{')) ++count;
        else if (str === false && (c == ']' || c == '}')) --count;
        else if (str === false && count == 0 && c == ',') {
          res.push(processValue(content));
          content = "";
          continue;
        }
        content += c;
      }
      if (content.length > 0) res.push(processValue(content));
      return res;
    }

    return val;
  }

  function processBlock(blocks) {
    let res = {}, level = -1, currentObj = null, isMap = true, processedBlocks = [];
    for (let j = 0, lenJ = blocks.length; j < lenJ; ++j) {
      if (level != -1 && level != blocks[j].level) continue;
      processedBlocks.push(j);
      level = blocks[j].level;
      const lines = blocks[j].lines;
      const children = blocks[j].children;

      for (let i = 0, len = lines.length; i < len; ++i) {
        const line = lines[i];
        let m = line.match(regex.key);
        if (m) {
          let key = m[1];
          if (key[0] == '-') {
            key = key.replace(regex.item, "");
            if (isMap) {
              isMap = false;
              if (typeof res.length === "undefined") res = [];
            }
            if (currentObj != null) res.push(currentObj);
            currentObj = {};
            isMap = true;
          }
          if (typeof m[2] != "undefined") {
            const value = m[2].replace(regex.trim, "");
            if (currentObj != null) currentObj[key] = processValue(value);
            else res[key] = processValue(value);
          }
        }
      }
      if (currentObj != null) {
        if (isMap) {
          isMap = false;
          if (typeof res.length === "undefined") res = [];
        }
        res.push(currentObj);
      }
    }
    for (let j = processedBlocks.length - 1; j >= 0; --j) blocks.splice.call(blocks, processedBlocks[j], 1);
    return res;
  }

  this.parse = function(str) {
    const pre = str.split("\n").filter(line => !regex.invalidLine.test(line)).join("\n");
    const doc = parser(pre);
    return processBlock(doc.children);
  };
}

const YAML = new YAMLParser();

// 参数解析
function parseParameters(link) {
  const para = /^(http|https)\:\/\//.test(link) ? link : link.split("\n")[0];
  const para1 = para.includes("#") ? para.split("#")[1].replace(/\$type/g, "node_type_para_prefix").replace(/\$emoji/g, "node_emoji_flag_prefix").replace(/\$tag/g, "node_tag_prefix").replace(/\$index/g, "node_index_prefix") : "";
  const mark0 = para.includes("#");
  return {
    Pin0: mark0 && para1.includes("in=") ? para1.split("in=")[1].split("&")[0].split("+").map(decodeURIComponent) : null,
    Pout0: mark0 && (para.includes("#out=") || para.includes("&out=")) ? (para.includes("#out=") ? para.split("#out=") : para.split("&out="))[1].split("&")[0].split("+").map(decodeURIComponent) : null,
    Preg: mark0 && para1.includes("regex=") ? decodeURIComponent(para1.split("regex=")[1].split("&")[0]).replace(/\，/g, ",") : null,
    Pregout: mark0 && para1.includes("regout=") ? decodeURIComponent(para1.split("regout=")[1].split("&")[0]).replace(/\，/g, ",") : null,
    Prname: mark0 && /(^|\&)rename=/.test(para1) ? para1.split(/(^|\&)rename=/)[2].split("&")[0].split("+") : null,
    Pemoji: mark0 && para1.includes("emoji=") ? para1.split("emoji=")[1].split("&")[0] : null,
    Pudp0: mark0 && para1.includes("udp=") ? para1.split("udp=")[1].split("&")[0] : 0,
    Ptfo0: mark0 && para1.includes("tfo=") ? para1.split("tfo=")[1].split("&")[0] : 0,
    Pcert0: mark0 && para1.includes("cert=") ? para1.split("cert=")[1].split("&")[0] : 0
  };
}

// 类型检查
function Type_Check(subs) {
  const RuleK = ["host,", "-suffix,", "domain,", "-keyword,", "ip-cidr,", "ip-cidr6,", "geoip,", "user-agent,", "ip6-cidr,", "ip-asn"];
  const QuanXK = ["shadowsocks=", "trojan=", "vmess=", "http=", "socks5="];
  const SurgeK = ["=ss,", "=vmess,", "=trojan,", "=http,", "=custom,", "=https,", "=shadowsocks", "=shadowsocksr", "=sock5", "=sock5-tls"];
  const ClashK = ["proxies:"];
  const SubK = ["dm1lc3M", "c3NyOi8v", "CnNzOi8", "dHJvamFu", "c3M6Ly", "c3NkOi8v", "c2hhZG93", "aHR0cDovLw", "aHR0cHM6L", "CnRyb2phbjo", "aHR0cD0", "aHR0cCA"];
  const SubK2 = ["ss://", "vmess://", "ssr://", "trojan://", "ssd://", "\nhttps://", "\nhttp://", "socks://", "ssocks://", "vless://"];
  const RewriteK = [" url 302", " url 307", " url reject", " url script", " url req", " url res", " url echo"];
  const subi = subs.replace(/ /g, "");
  const subsn = subs.split("\n");

  const NodeCheck = (item) => subi.toLowerCase().indexOf(item.toLowerCase()) != -1;
  const RewriteCheck = (item) => subs.includes(item);

  if (ClashK.some(NodeCheck)) return "Clash";
  if (RewriteK.some(RewriteCheck)) return "rewrite";
  if (RuleK.some(NodeCheck)) return "Rule";
  if (subsn.length >= 1 && SubK2.some(NodeCheck)) return "Subs";
  if (subi.includes("tag=") && QuanXK.some(NodeCheck)) return "QuanX";
  if (subs.includes("[Proxy]") || SurgeK.some(NodeCheck)) return "Surge";
  if (SubK.some(NodeCheck)) return "Subs-B64Encode";
  return "unknown";
}

// 订阅到 Quantumult X 格式转换
function Subs2QX(content, pudp0, ptfo0, pcert0, ptls13) {
  const lines = content.split("\n").filter(Boolean);
  let result = [];
  for (let line of lines) {
    if (line.startsWith("ss://") || line.startsWith("vmess://") || line.startsWith("trojan://")) {
      result.push(line); // 简化处理，实际需要解析协议
    }
  }
  return result.join("\n");
}

// 节点过滤
function Filter(nodes, Pin0, Pout0) {
  if (!Pin0 && !Pout0) return nodes;
  return nodes.filter(node => {
    const tag = node.match(/tag=(.+)/)?.[1] || "";
    let keep = true;
    if (Pin0) keep = Pin0.some(keyword => tag.includes(keyword));
    if (Pout0) keep = keep && !Pout0.some(keyword => tag.includes(keyword));
    return keep;
  });
}

// 正则过滤
function Regex(node) {
  return Preg ? node.match(new RegExp(Preg, "i")) ? node : null : node;
}

function RegexOut(node) {
  return Pregout ? node.match(new RegExp(Pregout, "i")) ? null : node : node;
}

// 重命名
function Rename(node) {
  let tag = node.match(/tag=(.+)/)?.[1] || "";
  if (!tag) return node;
  for (let rn of Prname) {
    const [oldName, newName] = rn.split("@");
    if (oldName && newName) {
      tag = tag.replace(new RegExp(escapeRegExp(oldName), "g"), newName);
    } else if (oldName && oldName.includes("☠️")) {
      tag = tag.replace(new RegExp(escapeRegExp(oldName.replace("☠️", "")), "g"), "");
    }
  }
  return node.replace(/tag=.+/, `tag=${tag}`);
}

function escapeRegExp(str) {
  return str.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
}

// Emoji 处理
function emoji_handle(nodes, Pemoji) {
  if (!Pemoji) return nodes;
  const emojiMap = {
    "香港": "🇭🇰",
    "台湾": "🇹🇼",
    "日本": "🇯🇵",
    "美国": "🇺🇸"
    // 更多映射可根据需要添加
  };
  return nodes.map(node => {
    let tag = node.match(/tag=(.+)/)?.[1] || "";
    if (Pemoji == "1") {
      for (let [key, emoji] of Object.entries(emojiMap)) {
        if (tag.includes(key)) tag = `${emoji} ${tag}`;
      }
    } else if (Pemoji == "-1") {
      for (let emoji of Object.values(emojiMap)) {
        tag = tag.replace(emoji, "");
      }
    }
    return node.replace(/tag=.+/, `tag=${tag.trim()}`);
  });
}

// 主解析函数
function ResourceParse() {
  const link0 = $resource.link || "";
  let content0 = $resource.content || "";
  const subtag = $resource.tag || "Parsed Subscription";
  const typeU = $resource.type || "unsupported";

  // 参数解析
  const params = parseParameters(link0);
  const { Pin0, Pout0, Preg, Pregout, Prname, Pemoji, Pudp0, Ptfo0, Pcert0 } = params;
  Preg = params.Preg; // 全局变量用于 Regex
  Pregout = params.Pregout; // 全局变量用于 RegexOut
  Prname = params.Prname; // 全局变量用于 Rename

  const type0 = Type_Check(content0);
  let total = "", flag = 1;

  if (type0 === "Subs-B64Encode") {
    total = Subs2QX(Base64.decode(content0), Pudp0, Ptfo0, Pcert0, 0);
  } else if (type0 === "Subs" || type0 === "QuanX" || type0 === "Surge" || type0 === "Clash") {
    total = Subs2QX(content0, Pudp0, Ptfo0, Pcert0, 0);
  } else if (type0 === "rewrite") {
    flag = 2;
    total = content0.split("\n").filter(Boolean).join("\n");
  } else if (type0 === "Rule") {
    flag = 3;
    total = content0.split("\n").map(item => item.trim()).filter(Boolean).join("\n");
  } else {
    $notify("❌ 解析错误", `订阅 ${subtag} 类型未知: ${type0}`, "请检查订阅内容", { "open-url": link0 });
    return "";
  }

  if (flag === 1) {
    total = total.split("\n").filter(Boolean);
    if (Pin0 || Pout0) total = Filter(total, Pin0, Pout0);
    if (Preg) total = total.map(Regex).filter(Boolean);
    if (Pregout) total = total.map(RegexOut).filter(Boolean);
    if (Prname) total = total.map(Rename);
    if (Pemoji) total = emoji_handle(total, Pemoji);
    total = total.join("\n");
    if (total) total = Base64.encode(total);
    else {
      $notify("⚠️ 解析结果为空", `订阅 ${subtag} 无有效节点`, "请检查参数或原始链接", { "open-url": link0 });
      return "";
    }
  }

  return total;
}

// 主入口
try {
  const total = ResourceParse();
  $done({ content: total });
} catch (err) {
  $notify("❌ 解析失败", "发生错误", String(err), { "open-url": "https://t.me/Shawn_Parser_Bot" });
  $done({ content: "" });
}
