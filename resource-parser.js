/**
 * 参考 KOP-XIAO resource-parser.js
 * 功能：节点 URI → Quantumult X 节点格式
 *      Surge/Shadowrocket 规则集 → Quantumult X 规则语法
 * 参数支持：in, out, regex, rename, sort, policy
 */

(function() {
  // -------- helpers --------
  function safeAtob(s) {
    if (typeof atob === 'function') return atob(s);
    try { return Buffer.from(s, 'base64').toString('binary'); } catch(e) { return null; }
  }
  function b64DecodeUnicode(str) {
    if (!str) return null;
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    try {
      const bin = safeAtob(str);
      if (bin === null) return null;
      return decodeURIComponent(Array.prototype.map.call(bin, function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join(''));
    } catch(e) {
      return null;
    }
  }
  function tryBase64DecodeIfLooksLike(s) {
    if (!s || s.length < 8) return null;
    if (/^[A-Za-z0-9\-_+=\/]+$/.test(s.trim())) {
      return b64DecodeUnicode(s.trim());
    }
    return null;
  }
  function splitOnce(str, sep) {
    const idx = str.indexOf(sep);
    if (idx === -1) return [str];
    return [str.slice(0, idx), str.slice(idx + sep.length)];
  }
  function safeTrim(s) { return (s || '').trim(); }

  function parseParams(paramString) {
    const params = {};
    if (!paramString) return params;
    paramString.split('&').forEach(p => {
      if (!p) return;
      const [k, ...rest] = p.split('=');
      const v = rest.join('=');
      if (!k) return;
      try { params[k] = decodeURIComponent(v || ''); } catch(e) { params[k] = v || ''; }
    });
    return params;
  }

  // -------- protocol parsers (节点) --------
  function parseVmess(line) {
    // vmess://base64json
    const without = line.replace(/^vmess:\/\//i, '');
    const [payload, frag] = without.split('#');
    let decoded = tryBase64DecodeIfLooksLike(payload) || payload;
    let json;
    try { json = JSON.parse(decoded); } catch(e) { 
      // 有些 vmess 链接里直接是 JSON 后面带参数
      try { json = JSON.parse(decodeURIComponent(payload)); } catch(e2) { json = null; }
    }
    if (!json) return null;
    const server = json.add || json.server || '';
    const port = json.port || '';
    const uuid = json.id || json.uuid || '';
    const ps = json.ps || json.remarks || json.remarks || '';
    const network = (json.net || json.network || '').toLowerCase();
    const tls = (json.tls === 'tls' || json.tls === '1' || json.tls === true);
    const host = json.host || json.sni || '';
    const path = json.path || json.wsPath || json.path || '';
    const alpn = json.alpn || '';

    let out = `vmess=${server}:${port}, method=none, password=${uuid}, tag=${ps || (server + ':' + port)}, fast-open=false, udp-relay=false`;
    if (network === 'ws') {
      out += `, obfs=${tls ? 'wss' : 'ws'}`;
      if (path) out += `, obfs-uri=${path}`;
      if (host) out += `, obfs-host=${host}`;
    } else {
      if (tls) {
        out += `, obfs=over-tls`;
        if (host) out += `, obfs-host=${host}`;
      }
      // 其他网络类型暂不处理专门路径
    }
    if (alpn) out += `, alpn=${alpn}`;
    return { name: ps || (server + ':' + port), qx: out, raw: line };
  }

  function parseSS(line) {
    // ss:// 或 ss://base64 或带 plugin
    let l = line.replace(/^ss:\/\//i, '');
    let tag = '';
    if (l.includes('#')) {
      const parts = l.split('#');
      l = parts[0];
      tag = decodeURIComponent(parts.slice(1).join('#')) || '';
    }
    // plugin 部分
    const [main, pluginPart] = splitOnce(l, '?');
    let info = main;
    // 如果没有 '@'，可能是 base64
    if (!main.includes('@')) {
      const dec = tryBase64DecodeIfLooksLike(main) || main;
      info = dec;
    }
    const m = info.match(/^([^:]+):([^@]+)@([^:]+):(\d+)$/);
    if (!m) return null;
    const method = m[1];
    const passwd = m[2];
    const host = m[3];
    const port = m[4];
    let obfs = '';
    let obfsHost = '';
    let obfsUri = '';
    if (pluginPart) {
      const kvs = pluginPart.split(';');
      kvs.forEach(kv => {
        const [k, v] = splitOnce(kv, '=');
        if (!k) return;
        const kl = k.toLowerCase();
        if (kl === 'plugin' && v) {
          // plugin=obfs-local;obfs=http; …
          // 可能多个插件参数
        }
        if (kl.includes('obfs') && v) {
          if (v === 'http' || v === 'ws' || v === 'wss') obfs = v;
        }
        if (kl === 'obfs-host') obfsHost = v || '';
        if (kl === 'obfs-uri') obfsUri = v || '';
      });
    }
    let out = `shadowsocks=${host}:${port}, method=${method}, password=${passwd}, tag=${tag || (host + ':' + port)}, fast-open=false, udp-relay=false`;
    if (obfs) out += `, obfs=${obfs}`;
    if (obfsHost) out += `, obfs-host=${obfsHost}`;
    if (obfsUri) out += `, obfs-uri=${obfsUri}`;
    return { name: tag || (host + ':' + port), qx: out, raw: line };
  }

  function parseTrojan(line) {
    // trojan://password@host:port etc
    let l = line.replace(/^trojan:\/\//i, '');
    let tag = '';
    if (l.includes('#')) {
      const parts = l.split('#');
      l = parts[0];
      tag = decodeURIComponent(parts.slice(1).join('#')) || '';
    }
    const [main, paramPart] = splitOnce(l, '?');
    const m = main.match(/^([^@]+)@(.+):(\d+)$/);
    if (!m) return null;
    const passwd = m[1];
    const host = m[2];
    const port = m[3];
    const params = {};
    if (paramPart) {
      paramPart.split('&').forEach(p => {
        const [k,v] = splitOnce(p, '=');
        if (k) params[k] = v || '';
      });
    }
    let out = `trojan=${host}:${port}, password=${passwd}, tag=${tag || (host + ':' + port)}, over-tls=true, tls-verification=false, fast-open=false, udp-relay=false`;
    if (params.sni) out += `, tls-host=${params.sni}`;
    return { name: tag || (host + ':' + port), qx: out, raw: line };
  }

  function parseQXNative(line) {
    // 如果已经是 QX 支持格式，直接返回
    const m = line.match(/^(vmess=|shadowsocks=|trojan=)/i);
    if (m) {
      // 提取 tag
      const tagMatch = line.match(/tag=([^,]+)/i);
      const name = tagMatch ? safeTrim(tagMatch[1]) : safeTrim(line.slice(0, 40));
      return { name: name, qx: safeTrim(line), raw: line };
    }
    return null;
  }

  function parseNodeLine(line) {
    line = safeTrim(line);
    if (!line) return null;
    // native
    const native = parseQXNative(line);
    if (native) return native;
    if (/^vmess:\/\//i.test(line)) return parseVmess(line);
    if (/^ssr:\/\//i.test(line)) return null; // SSR 若要支持, 可以在此实现
    if (/^ss:\/\//i.test(line)) return parseSS(line);
    if (/^trojan:\/\//i.test(line)) return parseTrojan(line);
    return null;
  }

  // -------- rules parser --------
  function convertRuleLine(line) {
    const l = safeTrim(line);
    if (!l) return null;
    // ignore comments
    if (/^#|^;|^\/\//.test(l)) return null;

    const parts = l.split(',');
    if (parts.length < 2) return l; // 无法拆成 TYPE,pattern,action,直接返回

    const type = parts[0].toUpperCase().trim();
    const pattern = parts[1].trim();
    const action = parts[2] ? safeTrim(parts[2]) : '';

    switch (type) {
      case 'DOMAIN-SUFFIX':
        return `host-suffix, ${pattern}, ${action}`;
      case 'DOMAIN-KEYWORD':
        return `host-keyword, ${pattern}, ${action}`;
      case 'DOMAIN':
        return `host, ${pattern}, ${action}`;
      case 'IP-CIDR':
        return `ip-cidr, ${pattern}, ${action}`;
      case 'FINAL':
        return `final, ${action}`;
      // 可以加更多 Surge 类型支持
      default:
        // 如果已经是 QX style (host-suffix, host, etc)，或其他类型则返回原行
        return l;
    }
  }

  // -------- filter / rename / sort --------
  function filterItems(items, params) {
    return items.filter(it => {
      if (!it) return false;
      // in
      if (params.in && !(it.name && it.name.includes(params.in))) return false;
      // out
      if (params.out && it.name && it.name.includes(params.out)) return false;
      if (params.regex) {
        try {
          const re = new RegExp(params.regex);
          if (!(it.raw && re.test(it.raw))) return false;
        } catch(e) {}
      }
      return true;
    });
  }
  function renameItems(items, params) {
    if (!params.rename) return items;
    const ops = params.rename.split('+');
    return items.map(it => {
      let name = it.name || '';
      ops.forEach(op => {
        const [oldStr, newStr] = splitOnce(op, '@');
        if (newStr !== undefined && oldStr) {
          name = name.split(oldStr).join(newStr);
        } else if (op.startsWith('@')) {
          name = name + op.slice(1);
        } else if (op.endsWith('@')) {
          name = op.slice(0, -1) + name;
        }
      });
      it.name = name;
      // 如果 qx 格式中有 tag=, 替换
      if (it.qx && it.qx.includes('tag=')) {
        it.qx = it.qx.replace(/tag=[^,]+/, 'tag=' + name);
      }
      return it;
    });
  }
  function sortItems(items, params) {
    if (!params.sort) return items;
    if (params.sort === '1') {
      return items.sort((a,b) => (a.name||'').localeCompare(b.name||''));
    }
    if (params.sort === '-1') {
      return items.sort((a,b) => (b.name||'').localeCompare(a.name||''));
    }
    if (params.sort.toLowerCase() === 'x') {
      return items.sort(() => Math.random() - 0.5);
    }
    return items;
  }

  // -------- main parse logic --------
  function isRuleFile(url, content) {
    // 判断是否是规则集
    if (/(\.rule|\.list|filter|rules)\b/i.test(url)) return true;
    // 看内容是否有 Surge 样式规则关键词
    const sample = content.split('\n').slice(0, 20).join('\n');
    if (/(DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR|FINAL)/i.test(sample)) return true;
    return false;
  }

  function isNodeFile(content) {
    if (/^vmess:\/\//i.test(content) || /^ss:\/\//i.test(content) || /^trojan:\/\//i.test(content)) return true;
    return false;
  }

  function process(url, content) {
    const [baseUrl, paramString] = url.split('#');
    const params = parseParams(paramString);

    if (isRuleFile(baseUrl, content)) {
      // 转换规则
      const lines = content.split('\n');
      const got = lines.map(line => {
        const conv = convertRuleLine(line);
        return conv;
      }).filter(l => l !== null);
      // 过滤 / 重命名 / 排序
      let items = got.map(l => ({ full: l, name: l, raw: l }));
      items = filterItems(items, params);
      items = renameItems(items, params);
      items = sortItems(items, params);
      if (params.policy) {
        items = items.map(it => {
          if (!it.full.includes(',policy=')) {
            it.full = it.full + `,policy=${params.policy}`;
          }
          return it;
        });
      }
      return items.map(it => it.full).join('\n');
    } else if (isNodeFile(content)) {
      const lines = content.split('\n');
      const items = lines.map(l => {
        const p = parseVmess(l) || parseSS(l) || parseTrojan(l) || parseQXNative(l);
        return p;
      }).filter(p => p !== null);
      let filtered = filterItems(items, params);
      filtered = renameItems(filtered, params);
      filtered = sortItems(filtered, params);
      return filtered.map(it => it.qx).join('\n');
    } else {
      // 两者都不是，默认原样返回
      return content;
    }
  }

  return { parse: process };
})();
