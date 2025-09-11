/** 
2⃣️ ⟦𝐫𝐞𝐰𝐫𝐢𝐭𝐞 重写⟧/⟦𝐟𝐢𝐥𝐭𝐞𝐫 分流⟧ ➠ 参数说明:
⦿ in, out, 根据关键词 保留/禁用 相关分流、重写规则;
⦿ inhn, outhn, “保留/删除”主机名(𝒉𝒐𝒔𝒕𝒏𝒂𝒎𝒆);
  ❖ 示范: 禁用 "淘宝比价" 及 "weibo" 的 js 同主机名
  𝐡𝐭𝐭𝐩𝐬://𝐦𝐲𝐥𝐢𝐬𝐭#out=tb_price.js+wb_ad.js&outhn=weibo
⦿ regex/regout, 正则保留/删除, 请自行折腾正则表达式;
  ❖ 可与 in(hn)/out(hn) 一起使用，in(hn)/out(hn) 会优先执行;
  ❖ 对 𝒉𝒐𝒔𝒕𝒏𝒂𝒎𝒆 & 𝐫𝐞𝐰𝐫𝐢𝐭𝐞/𝐟𝐢𝐥𝐭𝐞𝐫 同时生效(⚠️ 慎用)
⦿ policy 参数, 用于直接指定策略组，或为 𝐒𝐮𝐫𝐠𝐞 类型 𝗿𝘂𝗹𝗲-𝘀𝗲𝘁 生成策略组(默认"𝐒𝐡𝐚𝐰𝐧"策略组);
⦿ pset=regex1@policy1+regex2@policy2, 为同一分流规则中不同关键词(允许正则表达式)指定不同策略组;
⦿ replace 参数, 正则替换 𝐟𝐢𝐥𝐭𝐞𝐫/𝐫𝐞𝐰𝐫𝐢𝐭𝐞 内容, regex@newregex;
  ❖ 将淘宝比价中脚本替换成 lite 版本(如有此版本的脚本)
    ∎ replace=(price)(.*)@$1_lite$2
⦿ dst=rewrite/filter，分别为将 𝐦𝐨𝐝𝐮𝐥𝐞&𝗿𝘂𝗹𝗲-𝘀𝗲𝘁 转换成 重写/分流;
  ❖ ⚠️ 默认将 𝐦𝐨𝐝𝐮𝐥𝐞 转换到重写, 𝗿𝘂𝗹𝗲-𝘀𝗲𝘁 转成分流
  ❖ ⚠️ 把 𝗿𝘂𝗹𝗲-𝘀𝗲𝘁 中 url-regex 转成重写时, 必须要加 dst=rewrite;
  ❖ ⚠️ 把 𝐦𝐨𝐝𝐮𝐥𝐞 中的分流规则转换时, 必须要加 dst=filter
⦿ cdn=1, 将 github 脚本的地址转换成免翻墙 fastly.jsdelivr.net/gh
⦿ fcr=1/2/3, 为分流规则添加 force-cellular/multi-interface/multi-interface-balance 参数，强制移动数据/混合数据/负载均衡
⦿ via=接口, 为分流规则添加 via-interface 参数, 0 表示 via-interface=%TUN%
⦿ relay=目标策略名, 批量将节点订阅转换为ip/host规则，用于实现代理链

//判断订阅类型
function Type_Check(subs) {
    var type = "unknown"
    var RuleK = ["host,", "-suffix,", "domain,", "-keyword,", "ip-cidr,", "ip-cidr6,",  "geoip,", "user-agent,", "ip6-cidr,", "ip-asn"];
    var DomainK = ["domain-set,"]
    var QuanXK = ["shadowsocks=", "trojan=", "vmess=", "http=", "socks5="];
    var SurgeK = ["=ss,", "=vmess,", "=trojan,", "=http,", "=custom,", "=https,", "=shadowsocks", "=shadowsocksr", "=sock5", "=sock5-tls"];
    var ClashK = ["proxies:"]
    var SubK = ["dm1lc3M", "c3NyOi8v", "CnNzOi8", "dHJvamFu", "c3M6Ly", "c3NkOi8v", "c2hhZG93", "aHR0cDovLw", "aHR0cHM6L", "CnRyb2phbjo", "aHR0cD0", "aHR0cCA","U1RBVFVT"];
    var RewriteK = [" url 302", " url 307", " url reject", " url script", " url req", " url res", " url echo", " url-and-header 302", " url-and-header 307", " url-and-header reject", " url-and-header script", " url-and-header req", " url-and-header res", " url-and-header echo", " url jsonjq"] // quantumult X 类型 rewrite
    var SubK2 = ["ss://", "vmess://", "ssr://", "trojan://", "ssd://", "\nhttps://", "\nhttp://","socks://","ssocks://","vless://"];
    var ModuleK = ["[Script]", "[Rule]", "[URL Rewrite]", "[Map Local]", "\nhttp-r", "script-path"]
    var QXProfile = ["[filter_local]","[filter_remote]","[server_local]","[server_remote]"]
    var html = "DOCTYPE html"
    var subi = subs.replace(/ /g, "")
    const RuleCheck = (item) => subi.toLowerCase().indexOf(item) != -1;
    const NodeCheck = (item) => subi.toLowerCase().indexOf(item.toLowerCase()) != -1;
    const NodeCheck1 = (item) => subi.toLowerCase().indexOf(item.toLowerCase()) != -1; //b64加密的订阅类型
    const NodeCheck2 = (item) => subi.toLowerCase().indexOf(item.toLowerCase()) != -1; //URI 类型
    const RewriteCheck = (item) => subs.indexOf(item) != -1 ; // quanx 重写判定
    const ProfileCheck = (item) => subs.indexOf(item) != -1; //是否为quanx配置文件
    var subsn = subs.split("\n")
    if ( (subs.indexOf(html) != -1 || subs.indexOf("doctype html") != -1) && link0.indexOf("github.com" == -1)) {
      $notify("‼️ 该链接返回为无效网页内容"+ " ➟ " + "⟦" + subtag + "⟧", "⁉️ 点通知跳转以确认链接是否失效\n"+link0, "返回内容如下⬇️：\n"+subs, nan_link);
      type = "web";
    } else if (typeU == "nodes" && typeQ=="server") { //指定为节点类型
      type = (typeQ == "unsupported" || typeQ =="server")? "Subs":"wrong-field"
    } else if (ClashK.some(NodeCheck) || typeU == "clash"){ // Clash 类型节点转换
      type = (typeQ == "unsupported" || typeQ =="server")? "Clash":"wrong-field";
      typec = "server"
      content0 = Clash2QX(subs)
    } else if ( (((ModuleK.some(RewriteCheck) || para1.indexOf("dst=rewrite") != -1) && (para1.indexOf("dst=filter") == -1) && subs.indexOf("[Proxy]") == -1) || typeU == "module") && typeU != "nodes" && typeU != "rule" && typeQ !="filter") { // Surge 类型 module /rule-set(含url-regex) 类型
      typec="rewrite"
      type = (typeQ == "unsupported" || typeQ =="rewrite")? "sgmodule" : "wrong-field"
    } else if ((/(^hostname|\nhostname)\s*\=/.test(subi) || RewriteK.some(RewriteCheck))  && para1.indexOf("dst=filter")==-1 && subi.indexOf("securehostname") == -1 && !/module|nodes|rule/.test(typeU) && !(RuleK.some(RuleCheck) && typeQ == "filter") && !(typeQ!= "rewrite" && QXProfile.some(ProfileCheck))) {
      // 2022-07-20 remove constrain && !/\[(Proxy|filter_local)\]/.test(subs)
      typec = "rewrite"
      type = (typeQ == "unsupported" || typeQ =="rewrite")? "rewrite":"wrong-field" //Quantumult X 类型 rewrite/ Surge Script/
    } else if (((RuleK.some(RuleCheck) && subs.indexOf(html) == -1 ) || typeU == "rule" || para1.indexOf("dst=filter")!=-1) && typeU != "nodes" && !(typeQ == "server" && (QuanXK.some(NodeCheck) || SurgeK.some(NodeCheck))) ) {
      // rule/filter类型
      // 2022-07-20 remove constrain && !/\[(Proxy|server_local)\]/.test(subs) adter html
      typec = "filter"
      type = (typeQ == "unsupported" || typeQ =="filter")? "Rule":"wrong-field";
    } else if (typeU == "domain-set") {// 仅限用户指定为 domain-set；((DomainK.some(RuleCheck) || typeU == "domain-set") && subs.indexOf("[Proxy]") == -1 && typeU != "nodes") {
      typec = "filter-domain-set"
      type = (typeQ == "unsupported" || typeQ =="filter")? "Rule":"wrong-field";
      content0 = Domain2Rule(content0) // 转换 domain-set
    } else if (typeQ == "filter" && subs.indexOf("payload:")==-1) { // 纯 list类型？
      typec = "filter-list"
      type = (typeQ == "unsupported" || typeQ =="filter")? "Rule":"wrong-field";
      content0 = content0.split("\n").map(rule_list_handle).join("\n")
    } else if (subi.indexOf("sub://") == 0) { // sub:// 类型
      typec = "sub-http"
      type = "sub-http"
    } else if (typeQ == "filter" && subs.indexOf("payload:")!=-1) { // clash-provider 类型？
      typec = "Clash-Provider"
      type = (typeQ == "unsupported" || typeQ =="filter")? "Rule":"wrong-field";
    } else if (subsn.length >= 1 && SubK2.some(NodeCheck2) && !/\[(Proxy|filter_local)\]/.test(subs)) { //未b64加密的多行URI 组合订阅
      typec = "server-uri"
      type= (typeQ == "unsupported" || typeQ =="server" || typeQ =="uri") ? "Subs":"wrong-field"
    } else if ((subi.indexOf("tag=") != -1 && QuanXK.some(NodeCheck) && !/\[(Proxy|filter_local)\]/.test(subs)) || typeU =="list") {
      typec = "server-quanx"
      type = (typeQ == "unsupported" || typeQ =="server" || typeQ =="uri")? "Subs":"wrong-field" // QuanX list
    } else if (subs.indexOf("[Proxy]") != -1) {
      typec= "server-surge"
      type = (typeQ == "unsupported" || typeQ =="server" || typeQ =="uri")? "Surge":"wrong-field"; // Surge Profiles
      content0 = Surge2QX(content0).join("\n");
    } else if ((SurgeK.some(NodeCheck)  && !/\[(Proxy|filter_local)\]/.test(subs)) || typeU == "list") {
      typec="server-surge"
      type = (typeQ == "unsupported" || typeQ =="server" || typeQ =="uri")? "Subs":"wrong-field" // Surge proxy list
    } else if (subs.indexOf("[server_local]") != -1 && QuanXK.some(NodeCheck)) {
      //type = "QuanX"  // QuanX Profile
      typec="server-quanx"
      type = (typeQ == "unsupported" || typeQ =="server"|| typeQ =="uri")? "Subs":"wrong-field"
    } else if (content0.indexOf("server") !=-1 && content0.indexOf("server_port") !=-1) { //SIP008
      //type = "QuanX"
      typec= "server-sip008"
      type = (typeQ == "unsupported" || typeQ =="server")? "Subs":"wrong-field"
      content0 = SIP2QuanX(content0)
    } else if (SubK.some(NodeCheck1)) {  //b64加密的订阅类型
      typec="server-b64"
      type = (typeQ == "unsupported" || typeQ =="server")? "Subs-B64Encode":"wrong-field"
      if (content0.split("\n").length >= 2) { //  local snippet and first line remarks
        let tmp = content0.split("\n")[1]
        if (Pdbg) {$notify("local", "node", "\ntmp:\n"+tmp)}
        if (SubK.some((item) => tmp.toLowerCase().indexOf(item.toLowerCase()) != -1))
        content0 = tmp
      }
    } else if (QXProfile.every(ProfileCheck)) {
      typec = "profile"
      type = "profile"  //默认配置类型
    }else if (/\.js/.test(link0)) { // xjb添加js脚本的行为
      Perror = 1 ; // 无需反馈
      $notify("⚠️ 你导入的链接内容为 JS 脚本","🚥 脚本内未有重写规则，无法解析使用", " 请⚠️不要⚠️跑来解析器🤖️反馈 \n"+link0)
      type = "JS-0"
    } else if (typeQ =="server" && subs.length>100) { // 一些未知的b64 encode server case
      typec="server-b64-unknown"
      type = (typeQ == "unsupported" || typeQ =="server")? "Subs-B64Encode":"wrong-field"
    } else if(subs == "wrong-link") {
      type="wrong-link"
    }
    //else if (typeQ == "URI")
  // 用于通知判断类型，debug
  if(typeU == "X"){
    $notify("该链接判定类型",type+" : " +typec, subs)
  }
  //$notify(type)
    return type
}
