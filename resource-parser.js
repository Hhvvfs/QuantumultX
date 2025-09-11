/*
Quantumult X Resource Parser (Extracted for Node and Rule Conversion)
by Grok (Based on KOP-XIAO's resource-parser.js)
Version: Simplified for standalone use
Support: Subscription nodes (VMess, Trojan, VLESS, SS/SSR) and Divert Rules (Surge/Clash to QX)

Usage:
- For nodes: Call Subs2QX(content, udp=0, tfo=0, cert=0, tls13=0)
- For rules: Call Rule_Handle(lines, outKeywords=[], inKeywords=[])

Note: This is an extracted and simplified version focused on conversion. For full features, use the original.
*/

const isQX = typeof $task !== "undefined";

// Base64 Helper
const Base64 = {
  encode: str => Buffer.from(str).toString('base64'),
  decode: str => Buffer.from(str, 'base64').toString('utf-8')
};

// Extracted Node Conversion: Subs2QX
function Subs2QX(subs, Pudp, Ptfo, Pcert, PTls13) {
  subs = subs.split("\n").map(item => item.trim()).filter(Boolean);
  let QX = subs.map(S2QX).filter(Boolean);
  return QX.join("\n");
}

function S2QX(str) {
  if (/^vmess\s*=/i.test(str)) return VM2QX(str);
  if (/^ss\s*=/i.test(str)) return SS2QX(str);
  if (/^ssr\s*=/i.test(str)) return SSR2QX(str);
  if (/^trojan\s*=/i.test(str)) return TJ2QX(str);
  if (/^http\s*=/i.test(str)) return HTTP2QX(str);
  if (/^vless\s*=/i.test(str)) return VL2QX(str);
  return "";
}

// VMess to QX
function VM2QX(str) {
  let server = Base64.decode(str.split("vmess://")[1]);
  let node = "vmess = " + server;
  node = XUDP(node, Pudp);
  node = XTFO(node, Ptfo);
  return node;
}

// Shadowsocks to QX
function SS2QX(str) {
  let dat = str.match(/^ss:\/\/(.*)/);
  if (!dat) return;
  let node = "shadowsocks = " + Base64.decode(dat[1]);
  node = XUDP(node, Pudp);
  node = XTFO(node, Ptfo);
  return node;
}

// ShadowsocksR to QX
function SSR2QX(str) {
  let dat = str.match(/^ssr:\/\/(.*)/);
  if (!dat) return;
  let obfs = "plain";
  let nssr = Base64.decode(dat[1]).split("/?");
  let host = nssr[0].split(":");
  let par = QX_TLS(host[5], Pcert, PTls13);
  let pw = "password=" + Base64.decode(host[5]);
  let mtd = "method=" + host[4];
  let obfsh = host[3].indexOf("http") != -1 ? "http" : host[3];
  let protoh = host[2].indexOf("http") != -1 ? "http" : host[2];
  if (par != "" && protoh != "none") return;
  let node = "shadowsocks=" + host[0] + ":" + host[1] + ", " + mtd + ", " + pw + ", obfs=" + obfsh + ", obfs-host=" + protoh + ", tag=" + host[0];
  node = XUDP(node, Pudp);
  node = XTFO(node, Ptfo);
  return node;
}

// Trojan to QX
function TJ2QX(str) {
  let node = "trojan = " + str.split("trojan://")[1];
  let cert = Pcert == 0 ? "tls-verification=false" : "tls-verification=true";
  node = node.indexOf("tls-verification") == -1 ? node.replace(/tag\s*\=\s*/, cert + ", tag=") : node;
  node = XUDP(node, Pudp);
  node = XTFO(node, Ptfo);
  return node;
}

// HTTP to QX
function HTTP2QX(str) {
  let node = "http = " + str.split("http://")[1];
  let cert = Pcert == 0 ? "tls-verification=false" : "tls-verification=true";
  node = node.indexOf("tls-verification") == -1 ? node.replace(/tag\s*\=\s*/, cert + ", tag=") : node;
  node = XUDP(node, Pudp);
  node = XTFO(node, Ptfo);
  return node;
}

// VLESS to QX
function VL2QX(str) {
  let node = "vless = " + str.split("vless://")[1];
  let cert = Pcert == 0 ? "tls-verification=false" : "tls-verification=true";
  node = node.indexOf("tls-verification") == -1 ? node.replace(/tag\s*\=\s*/, cert + ", tag=") : node;
  node = XUDP(node, Pudp);
  node = XTFO(node, Ptfo);
  return node;
}

// UDP/TFO Helpers
function XUDP(cnt, pudp) {
  let udp = pudp == 1 ? "udp-relay=true, " : "udp-relay=false, ";
  return cnt.indexOf("udp-relay") != -1 ? cnt.replace(/udp-relay.*?,/, udp) : cnt.replace(/tag.*?=/, udp + "tag=");
}

function XTFO(cnt, ptfo) {
  let tfo = ptfo == 1 ? "fast-open=true, " : "fast-open=false, ";
  return cnt.indexOf("fast-open") != -1 ? cnt.replace(/fast-open.*?,/, tfo) : cnt.replace(/tag.*?=/, tfo + "tag=");
}

// Extracted Rule Conversion: Rule_Handle
function Rule_Handle(subs, Pout, Pin) {
  subs = subs.map(item => item.trim()).filter(Boolean);
  let nlist = [];
  let Rk = ["//", ";", "^http"];
  subs.forEach(rule => {
    if (!Rk.some(key => rule.indexOf(key) != -1) && rule != "" && rule != "[Rule]") {
      let aftr = RuleQX(rule.trim(), Pout, Pin);
      if (aftr != "" && aftr != "[]") nlist.push(aftr);
    }
  });
  return nlist;
}

function RuleQX(str) {
  let type = str.indexOf("DOMAIN-SET") != -1 ? "set" : "rule";
  if (type == "rule") {
    return QXRule(str);
  } else if (type == "set") {
    return QXSet(str);
  }
  return "";
}

// Simple QX Rule Conversion
function QXRule(str) {
  let res = "";
  if (str.indexOf("IP-CIDR") != -1 || str.indexOf("GEOIP") != -1) {
    res = `ip-cidr, ${str.split(",no-resolve")[0].split(",")[1].trim()}, Proxy`;
  } else if (str.indexOf("DOMAIN-SUFFIX") != -1) {
    res = `domain-suffix, ${str.split(",")[1].trim()}, Proxy`;
  } else if (str.indexOf("DOMAIN-KEYWORD") != -1) {
    res = `domain-keyword, ${str.split(",")[1].trim()}, Proxy`;
  } else if (str.indexOf("DOMAIN") != -1) {
    res = `domain, ${str.split(",")[1].trim()}, Proxy`;
  }
  return res;
}

// Domain-Set to QX (Simplified)
function QXSet(str) {
  // Assuming str is a domain-set rule; convert to individual domain rules
  let domains = str.split("\n").filter(Boolean); // Example handling
  return domains.map(domain => `domain, ${domain.trim()}, Proxy`).join("\n");
}

// Example Usage (Standalone Test)
if (isQX) {
  // Test Node Conversion
  let subContent = "vmess://base64encodedvmess"; // Replace with actual sub
  let convertedNodes = Subs2QX(subContent);
  console.log(convertedNodes);

  // Test Rule Conversion
  let ruleContent = ["DOMAIN-SUFFIX,example.com,Proxy", "IP-CIDR,192.168.0.0/16,Proxy"];
  let convertedRules = Rule_Handle(ruleContent);
  console.log(convertedRules.join("\n"));
} else {
  console.log("This script is for Quantumult X environment.");
}
