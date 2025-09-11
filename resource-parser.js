/**
 * Quantumult X 简化资源解析器
 * 只做两件事：
 * 1. 节点 URI 转换为 Quantumult X 节点格式
 * 2. 规则格式转换为 Quantumult X 规则格式
 */

(function() {
  // --------- base64 工具 ----------
  function safeAtob(s) {
    try { return atob(s); } catch (e) {
      try { return Buffer.from(s, 'base64').toString('binary'); } catch(e2) { return null; }
    }
  }
  function b64DecodeUnicode(str) {
    if (!str) return null;
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    try {
      const bin = safeAtob(str);
      return decodeURIComponent(bin.split('').map(c =>
        '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
      ).join(''));
    } catch(e) { return null; }
  }

  // --------- 节点解析 ----------
  function parseSS(line) {
    let l = line.replace(/^ss:\/\//i, '');
    let tag = '';
    if (l.includes('#')) {
      const arr = l.split('#');
      l = arr[0];
      tag = decodeURIComponent(arr.slice(1).join('#'));
    }
    if (!l.includes('@')) {
      l = b64DecodeUnicode(l) || l;
    }
    const m = l.match(/^([^:]+):([^@]+)@([^:]+):(\d+)/);
    if (!m) return null;
    const method = m[1], pwd = m[2], host = m[3], port = m[4];
    return `shadowsocks=${host}:${port}, method=${method}, password=${pwd}, fast-open=false, udp-relay=false, tag=${tag||host}`;
  }

  function parseVmess(line) {
    const body = line.replace(/^vmess:\/\//i, '');
    const decoded = b64DecodeUnicode(body);
    if (!decoded) return null;
    let obj;
    try { obj = JSON.parse(decoded); } catch(e) { return null; }
    const server = obj.add, port = obj.port, uuid = obj.id;
    const ps = obj.ps || `${server}:${port}`;
    let out = `vmess=${server}:${port}, method=none, password=${uuid}, fast-open=false, udp-relay=false, tag=${ps}`;
    if (obj.net === 'ws') {
      out += obj.tls === 'tls' ? ', obfs=wss' : ', obfs=ws';
      if (obj.path) out += `, obfs-uri=${obj.path}`;
      if (obj.host) out += `, obfs-host=${obj.host}`;
    } else if (obj.tls === 'tls') {
      out += ', obfs=over-tls';
      if (obj.host) out += `, obfs-host=${obj.host}`;
    }
    return out;
  }

  function parseTrojan(line) {
    let l = line.replace(/^trojan:\/\//i, '');
    let tag = '';
    if (l.includes('#')) {
      const arr = l.split('#');
      l = arr[0];
      tag = decodeURIComponent(arr.slice(1).join('#'));
    }
    const m = l.match(/^([^@]+)@([^:]+):(\d+)/);
    if (!m) return null;
    const pwd = m[1], host = m[2], port = m[3];
    return `trojan=${host}:${port}, password=${pwd}, over-tls=true, tls-verification=false, fast-open=false, udp-relay=false, tag=${tag||host}`;
  }

  function parseNode(line) {
    line = line.trim();
    if (!line) return null;
    if (/^ss:\/\//i.test(line)) return parseSS(line);
    if (/^vmess:\/\//i.test(line)) return parseVmess(line);
    if (/^trojan:\/\//i.test(line)) return parseTrojan(line);
    if (/^(vmess=|shadowsocks=|trojan=)/i.test(line)) return line; // 已是 QX 格式
    return null;
  }

  // --------- 规则解析 ----------
  function parseRule(line) {
    line = line.trim();
    if (!line || /^#|^;|^\/\//.test(line)) return null;
    const parts = line.split(',');
    if (parts.length < 2) return line;
    const type = parts[0].toUpperCase().trim();
    const val = parts[1].trim();
    const policy = parts[2] ? parts[2].trim() : '';

    switch (type) {
      case 'DOMAIN-SUFFIX': return `host-suffix, ${val}, ${policy}`;
      case 'DOMAIN':        return `host, ${val}, ${policy}`;
      case 'DOMAIN-KEYWORD':return `host-keyword, ${val}, ${policy}`;
      case 'IP-CIDR':       return `ip-cidr, ${val}, ${policy}`;
      case 'GEOIP':         return `geoip, ${val.toLowerCase()}, ${policy}`;
      case 'FINAL':         return `final, ${policy}`;
      default:              return line;
    }
  }

  // --------- 主入口 ----------
  function parse(url, content) {
    // 节点订阅
    if (/^((ss|vmess|trojan|ssr):\/\/|vmess=|shadowsocks=|trojan=)/i.test(content.trim())) {
      const lines = content.split('\n');
      return lines.map(parseNode).filter(Boolean).join('\n');
    }
    // 规则订阅
    if (/(DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR|FINAL|GEOIP)/i.test(content)) {
      const lines = content.split('\n');
      return lines.map(parseRule).filter(Boolean).join('\n');
    }
    // 其它内容直接返回
    return content;
  }

  return { parse };
})();
