/* =================================================================
 * Cloudflare Worker: All-in-One Proxy Tool (Strict Read-Only Version)
 * =================================================================
 * [SECURITY NOTE]: 
 * This version allows NO IP updates (Auto or Manual).
 * It ONLY reads existing data from the D1 Database.
 * ================================================================= */

// =================================================================
//  GLOBAL UTILITIES
// =================================================================

function utf8_to_b64(str) {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
        function toSolidBytes(match, p1) {
            return String.fromCharCode(parseInt(p1, 16));
        }));
}

function b64_to_utf8(str) {
    try {
        return decodeURIComponent(atob(str).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
    } catch (e) {
        console.error("Base64 decoding error:", e);
        throw new Error("无效的 Base64 字符串，无法解码 VMess 配置。");
    }
}

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data, null, 2), {
        status: status,
        headers: {
            'Content-Type': 'application/json;charset=UTF-8',
        },
    });
}

function getProtocol(configStr) {
    if (!configStr || typeof configStr !== 'string') return 'unknown';
    if (configStr.startsWith('vmess://')) return 'vmess';
    if (configStr.startsWith('vless://')) return 'vless';
    if (configStr.startsWith('trojan://')) return 'trojan';
    return 'unknown';
}


// =================================================================
//  SECTION 1: Data Fetching (STRICTLY READ ONLY)
// =================================================================

// 获取 IP (仅读取 SELECT)
async function fetchIpsFromDB(ipType, carrierType, env) {
    const db = env.DB;
    if (!db) throw new Error("D1 数据库未绑定。");

    let query = 'SELECT ip, ip_type, carrier FROM cfips WHERE 1=1';
    const params = [];

    if (ipType.toLowerCase() !== 'all') {
        query += ' AND ip_type = ?';
        params.push(ipType.toLowerCase());
    }
    if (carrierType.toLowerCase() !== 'all') {
        query += ' AND carrier = ?';
        params.push(carrierType.toUpperCase());
    }
    query += ' ORDER BY created_at DESC, ip_type DESC';

    const { results } = await db.prepare(query).bind(...params).all();
    return results;
}

// 获取域名 (仅读取 SELECT)
async function fetchDomainsFromDB(env) {
    const db = env.DB;
    if (!db) throw new Error("D1 数据库未绑定。");
    try {
        const { results } = await db.prepare('SELECT domain FROM cf_domains ORDER BY created_at DESC').all();
        return results;
    } catch (e) {
        console.error("Fetching domains failed:", e.message);
        return [];
    }
}

// 统一的批量获取接口
async function handleGetBatchAddresses(url, env) {
    const type = url.searchParams.get('type') || 'ip'; 

    try {
        if (type === 'domain') {
            const domainData = await fetchDomainsFromDB(env);
            if (domainData.length === 0) {
                return new Response("Database is empty (no domains found).", { status: 404 });
            }
            const listText = domainData.map(item => item.domain).join('\n');
            return new Response(listText, { headers: { 'Content-Type': 'text/plain;charset=UTF-8' } });
        } else {
            // IP 逻辑
            const ipType = url.searchParams.get('ipType') || 'all';
            const carrier = url.searchParams.get('carrier') || 'all';
            const ipData = await fetchIpsFromDB(ipType, carrier, env);
            
            if (ipData.length === 0) {
                return new Response(`No IPs found in DB for ipType=${ipType} and carrier=${carrier}.`, { status: 404 });
            }
            const listText = ipData.map(item => item.ip).join('\n');
            return new Response(listText, { headers: { 'Content-Type': 'text/plain;charset=UTF-8' } });
        }

    } catch (e) {
        console.error("Error in /batch-ip handler:", e.message);
        return new Response("Internal Error: " + e.message, { status: 500 });
    }
}


// =================================================================
//  SECTION 2: Config Generation Logic
// =================================================================

// 读取基础配置 (SELECT)
async function fetchConfigsByUuidFromDB(uuid, env) {
    const db = env.DB;
    if (!db) return [];
    try {
        const stmt = db.prepare('SELECT config_data FROM configs WHERE uuid = ? ORDER BY id ASC');
        const { results } = await stmt.bind(uuid).all();
        return results.map(row => row.config_data);
    } catch (e) {
        console.error(`Error fetching configs for UUID ${uuid}:`, e.message);
        return [];
    }
}

// 核心替换逻辑
function replaceAddressesInConfigs(baseConfigsToProcess, addressList) {
    let generatedConfigs = [];
    const addressExtractionRegex = /@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9a-fA-F:\.]+\]|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?::\d+)?(?:[\/?#]|$)/;
    const validAddressRegex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9a-fA-F:\.]+\]|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})$/;

    for (const baseConfig of baseConfigsToProcess) {
        let configType = getProtocol(baseConfig);
        let processedBaseConfig;
        const pushError = (msg) => generatedConfigs.push(`[错误] ${msg}`);

        if (configType === 'trojan' || configType === 'vless') {
            const addressMatch = baseConfig.match(addressExtractionRegex);
            if (!addressMatch) {
                pushError(`配置中未找到地址，已跳过。`);
                continue;
            }
            processedBaseConfig = baseConfig;
        } else if (configType === 'vmess') {
            const encodedJson = baseConfig.substring('vmess://'.length);
            try {
                let vmessObj = JSON.parse(b64_to_utf8(encodedJson));
                if (!vmessObj.add) {
                    pushError(`VMess配置中未找到 "add" 字段，已跳过。`);
                    continue;
                }
                processedBaseConfig = vmessObj;
            } catch (e) {
                pushError(`VMess配置解码失败，已跳过。`);
                continue;
            }
        } else {
            pushError(`不支持的类型，已跳过。`);
            continue;
        }

        for (const newAddr of addressList) {
            if (!validAddressRegex.test(newAddr) && !newAddr.includes(':')) {
                // simple validation
            }
            const cleanAddrForName = newAddr.replace(/[\[\]]/g, '');

            if (configType === 'trojan' || configType === 'vless') {
                try {
                    const url = new URL(processedBaseConfig);
                    const originalName = url.hash ? decodeURIComponent(url.hash.substring(1)) : `${configType}-node`;
                    const newName = `${originalName}-${cleanAddrForName}`;
                    url.hash = encodeURIComponent(newName);
                    url.hostname = newAddr; 
                    generatedConfigs.push(url.toString());
                } catch (e) {
                      pushError(`处理 ${configType} 出错: ${e.message}`);
                }
            } else if (configType === 'vmess') {
                const tempVmessObj = JSON.parse(JSON.stringify(processedBaseConfig));
                const originalName = tempVmessObj.ps || tempVmessObj.remark || 'vmess-node';
                tempVmessObj.ps = `${originalName}-${cleanAddrForName}`;
                tempVmessObj.add = newAddr; 
                if (tempVmessObj.remark) delete tempVmessObj.remark;

                try {
                    generatedConfigs.push(`vmess://${utf8_to_b64(JSON.stringify(tempVmessObj))}`);
                } catch (e) {
                    pushError(`VMess编码失败: ${e.message}`);
                }
            }
        }
    }
    return generatedConfigs;
}

// 手动 or UUID 生成 (POST)
async function generateConfigs(request, env) {
    try {
        const body = await request.json();
        const addressListText = body.addressList || body.ipList;
        const { baseConfigUuid, baseConfig: baseConfigFromRequest } = body;
        
        let baseConfigsToProcess = [];

        if (baseConfigUuid) {
            const configsFromDb = await fetchConfigsByUuidFromDB(baseConfigUuid, env);
            if (configsFromDb.length === 0) {
                return jsonResponse({ error: `未找到 UUID 为 "${baseConfigUuid}" 的任何基础配置。` }, 404);
            }
            baseConfigsToProcess = configsFromDb;
        } else if (baseConfigFromRequest) {
            baseConfigsToProcess = baseConfigFromRequest.split('\n').map(s => s.trim()).filter(Boolean);
            if (baseConfigsToProcess.length === 0) return jsonResponse({ error: "基础配置不能为空。" }, 400);
        } else {
            return jsonResponse({ error: "必须提供基础配置或UUID。" }, 400);
        }

        if (!addressListText || addressListText.trim() === '') {
            return jsonResponse({ error: "优选列表不能为空。" }, 400);
        }

        const addressList = addressListText.split('\n').map(a => a.trim()).filter(a => a.length > 0);
        const generatedConfigs = replaceAddressesInConfigs(baseConfigsToProcess, addressList);

        const successCount = generatedConfigs.filter(c => !c.startsWith('[错误]')).length;
        const errorCount = generatedConfigs.length - successCount;
        let message = `生成完成！成功 ${successCount} 条`
        if(errorCount > 0) message += `, 失败 ${errorCount} 条。`;
        
        return jsonResponse({ configs: generatedConfigs, message: message });
    } catch (e) {
        console.error("生成配置出错:", e.message);
        return jsonResponse({ error: "内部错误: " + e.message }, 500);
    }
}

// 订阅链接生成配置 (GET)
async function handleGetBatchConfigs(uuid, urlParams, env) {
    if (!uuid) return jsonResponse({ error: 'UUID Required' }, 400);

    const baseConfigs = await fetchConfigsByUuidFromDB(uuid, env);
    if (baseConfigs.length === 0) return jsonResponse({ error: `UUID Not Found` }, 404);

    const type = urlParams.get('type') || 'ip';
    let addressList = [];

    try {
        if (type === 'domain') {
            const domains = await fetchDomainsFromDB(env);
            addressList = domains.map(d => d.domain);
        } else {
            // IP
            const ipType = urlParams.get('ipType') || 'all';
            const carrier = urlParams.get('carrier') || 'all';
            const ips = await fetchIpsFromDB(ipType, carrier, env);
            addressList = ips.map(i => i.ip);
        }
    } catch (e) {
        return jsonResponse({ error: "DB Error: " + e.message }, 500);
    }

    if (addressList.length === 0) {
        return jsonResponse({ error: `No valid addresses found for type=${type}` }, 404);
    }

    const generatedConfigs = replaceAddressesInConfigs(baseConfigs, addressList);
    const filteredConfigs = generatedConfigs.filter(c => !c.startsWith('[错误]'));

    if (filteredConfigs.length === 0) {
        return new Response("Generation failed.", { status: 400 });
    }

    const body = btoa(filteredConfigs.join('\n'));

    return new Response(body, {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=UTF-8',
            'Subscription-User-Info': 'upload=0; download=0; total=10737418240000; expire=2524608000',
            'Profile-Update-Interval': '24',
        },
    });
}

// =================================================================
//  MAIN WORKER ROUTING AND EXPORT
// =================================================================

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;
        const DOMAIN_NAME = url.origin;
        const EXTERNAL_CONFIG_MANAGER_URL = "https://config-cfst.api.yangzifun.org/";

        const batchUUID = new URLPattern({ pathname: '/batch-configs/:uuid' });

        try {
            if (method === 'GET') {
                if (path === '/') {
                    return new Response(generatePageHtmlContent.replace(/YOUR_WORKER_DOMAIN_PATH/g, DOMAIN_NAME), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
                }
                
                // Redirect to Manager (External)
                if (path === '/manage') {
                    return Response.redirect(EXTERNAL_CONFIG_MANAGER_URL, 302);
                }

                // API: Get List Text
                if (path === '/batch-ip') {
                    return await handleGetBatchAddresses(url, env);
                }

                // API: Subscription
                const batchMatch = batchUUID.exec(url);
                if (batchMatch) {
                    return await handleGetBatchConfigs(batchMatch.pathname.groups.uuid, url.searchParams, env);
                }

                // API: Frontend Fetch (Strictly DB)
                if (path === '/fetch-addresses') {
                    const type = url.searchParams.get('type') || 'ip';
                    if (type === 'domain') {
                        const domains = await fetchDomainsFromDB(env);
                        return jsonResponse({ list: domains.map(d => d.domain), message: `获取到 ${domains.length} 个域名` });
                    } else {
                        // IP Logic: Force DB read, ignore any 'source=api' params
                        const ips = await fetchIpsFromDB(
                            url.searchParams.get('ipType') || 'all',
                            url.searchParams.get('carrierType') || 'all',
                            env
                        );
                        return jsonResponse({ list: ips.map(i => i.ip), message: `获取到 ${ips.length} 个IP` }); 
                    }
                }
                // Legacy API
                if (path === '/fetch-ips') {
                     const ips = await fetchIpsFromDB(url.searchParams.get('ipType') || 'all', url.searchParams.get('carrierType') || 'all', env);
                     return jsonResponse({ ips: ips.map(i => i.ip), message: `Success` });
                }
            }

            if (method === 'POST') {
                if (path === '/generate') return generateConfigs(request, env);
            }

            return new Response('404 Not Found', { status: 404 });
        } catch (err) {
            return new Response("Internal Error: " + err.message, { status: 500 });
        }
    },
    
    // [SECURITY] No scheduled() function is exported here.
    // This prevents Cloudflare from triggering any automatic Cron Triggers.
};

// =================================================================
//  SECTION 4: FRONTEND CONTENT
// =================================================================

const newGlobalStyle = `
html { font-size: 87.5%; }
body, html { margin: 0; padding: 0; min-height: 100%; background-color: #fff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
.container { width: 100%; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; padding: 40px 20px; box-sizing: border-box; }
.content-group { width: 100%; max-width: 700px; text-align: center; z-index: 10; box-sizing: border-box; }
.profile-name { font-size: 2.2rem; color: #3d474d; margin-bottom: 10px; font-weight: bold;}
.profile-quote { color: #89949B; margin-bottom: 27px; min-height: 1.2em; }
.nav-grid { display: flex; flex-wrap: wrap; justify-content: center; gap: 8px; margin-bottom: 27px; }
.nav-btn { display: inline-flex; align-items: center; justify-content: center; padding: 8px 16px; text-align: center; background: #E8EBED; border: 2px solid #89949B; border-radius: 4px; color: #5a666d; text-decoration: none !important; font-weight: 500; font-size: 0.95rem; line-height: 1.2; transition: all 0.3s; white-space: nowrap; cursor: pointer; box-sizing: border-box; }
.nav-btn:hover:not(:disabled) { background: #89949B; color: white; }
.nav-btn:disabled { opacity: 0.6; cursor: not-allowed;}
.nav-btn.primary { background-color: #5a666d; color: white; border-color: #5a666d;}
.nav-btn.primary:hover:not(:disabled) { background-color: #3d474d; }
.card { background: #f8f9fa; border: 1px solid #E8EBED; border-radius: 8px; padding: 24px; margin-bottom: 24px; text-align: left; }
.card h2 { font-size: 1.5rem; color: #3d474d; margin-top: 0; margin-bottom: 20px; text-align: center;}
.form-group { margin-bottom: 16px; }
.form-group label { display: block; color: #5a666d; font-weight: 500; margin-bottom: 8px; font-size: 0.9rem;}
textarea, input[type="text"] { width: 100%; padding: 10px; border: 2px solid #89949B; border-radius: 4px; background: #fff; font-family: 'SF Mono', 'Courier New', monospace; font-size: 0.9rem; box-sizing: border-box; resize: vertical; }
textarea:focus, input[type="text"]:focus { outline: none; border-color: #3d474d; }
.radio-group { display: flex; flex-wrap: wrap; gap: 10px; }
.radio-group label { padding: 6px 14px; background: #E8EBED; border: 2px solid #89949B; border-radius: 4px; color: #5a666d; font-size: 0.85rem; cursor: pointer; transition: all 0.3s; }
.radio-group input[type="radio"] { display: none; }
.radio-group input[type="radio"]:checked + span { background: #89949B; color: white; }
.radio-group label:hover { background: #d1d5d8; }
.radio-group input[type="radio"]:checked + span:hover { background: #89949B; color: white; }
.info-box { background-color: #e8ebed; color: #5a666d; border-left: 4px solid #89949B; padding: 12px 16px; border-radius: 4px; font-size: 0.85rem; text-align: left; line-height: 1.5; margin: 16px 0; }
.info-box a { color: #3d474d; font-weight: bold; text-decoration: none; word-break: break-all; }
.info-box a:hover { text-decoration: underline; }
.footer { margin-top: 40px; text-align: center; color: #89949B; font-size: 0.8rem; }
.footer a { color: #89949B; text-decoration: none; }
.footer a:hover { text-decoration: underline; }
.hidden { display: none; }
#toast-container { position: fixed; top: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; }
.toast { display: flex; align-items: center; padding: 12px 18px; border-radius: 4px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); font-weight: 500; font-size: 0.9rem; border: 2px solid #89949B; background: #fff; color: #3d474d; opacity: 0; transform: translateX(100%); animation: slideIn 0.5s forwards, fadeOut 0.5s 4.5s forwards; }
@keyframes slideIn { to { opacity: 1; transform: translateX(0); } }
@keyframes fadeOut { from { opacity: 1; } to { opacity: 0; transform: translateX(100%); } }
.loader { width: 16px; height: 16px; border: 2px solid white; border-bottom-color: transparent; border-radius: 50%; display: inline-block; box-sizing: border-box; animation: rotation 1s linear infinite; margin-right: 8px; }
@keyframes rotation { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
@media (max-width: 768px) { html { font-size: 100%; } .container { padding: 20px 15px; justify-content: flex-start; } .profile-name { font-size: 1.8rem; } .profile-quote { font-size: 0.95rem; margin-bottom: 20px; } .card { padding: 20px 15px; margin-bottom: 20px; } .card h2 { font-size: 1.3rem; } .nav-btn { padding: 9px 12px; font-size: 0.9rem; } }
`;

const generatePageHtmlContent = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="https://s3.yangzifun.org/logo.ico" type="image/x-icon">
  <title>YZFN 优选配置生成 (Read-Only)</title>
  <style>${newGlobalStyle}</style>
</head>
<body>
  <div id="toast-container"></div>
  <div class="container">
    <div class="content-group">
      <h1 class="profile-name">CF优选配置批量生成</h1>
      <p class="profile-quote">支持 IP 优选与域名优选的批量替换工具 (Database Mode)</p>

      <div class="nav-grid">
        <a href="/" class="nav-btn primary">批量生成</a>
        <a href="https://config-cfst.api.yangzifun.org/" target="_blank" class="nav-btn">配置管理</a>
      </div>

      <div class="card">
        <h2>1. 基础配置</h2>
        <div class="form-group radio-group">
            <label><input type="radio" name="genConfigSource" value="manual" checked><span>手动粘贴</span></label>
            <label><input type="radio" name="genConfigSource" value="uuid"><span>从UUID获取</span></label>
        </div>
        <div id="genManualConfigInput" class="form-group">
            <textarea id="genBaseConfigInput" placeholder="在此粘贴一个或多个基础配置，每行一个。" rows="6"></textarea>
        </div>
        <div id="genUuidConfigInput" class="form-group hidden">
            <input type="text" id="genBaseConfigUuidInput" placeholder="输入已存储的UUID，如 my-configs">
            <div class="info-box">在 <a href="https://config-cfst.api.yangzifun.org/" target="_blank">配置管理</a> 页面添加和管理UUID。</div>
        </div>
      </div>

      <div class="card">
        <h2>2. 优选列表 (IP/域名)</h2>
        <div class="form-group">
          <label>地址类型</label>
          <div class="radio-group">
            <label><input type="radio" name="genAddressType" value="ip" checked onchange="toggleAddressOptions()"><span>IP 地址</span></label>
            <label><input type="radio" name="genAddressType" value="domain" onchange="toggleAddressOptions()"><span>优选域名</span></label>
          </div>
        </div>

        <div id="ipOptionsContainer">
            <div class="form-group">
              <label>IP 类型</label>
              <div class="radio-group">
                <label><input type="radio" name="genIpType" value="all" checked><span>全部</span></label>
                <label><input type="radio" name="genIpType" value="v4"><span>仅IPv4</span></label>
                <label><input type="radio" name="genIpType" value="v6"><span>仅IPv6</span></label>
              </div>
            </div>
            <div class="form-group">
              <label>运营商</label>
              <div class="radio-group">
                <label><input type="radio" name="genCarrierType" value="all" checked><span>全部</span></label>
                <label><input type="radio" name="genCarrierType" value="CM"><span>移动</span></label>
                <label><input type="radio" name="genCarrierType" value="CU"><span>联通</span></label>
                <label><input type="radio" name="genCarrierType" value="CT"><span>电信</span></label>
              </div>
            </div>
        </div>

        <div id="domainInfoBox" class="info-box hidden">
           将使用数据库中存储的 Cloudflare 优选域名列表进行替换。
        </div>

        <button id="genFetchBtn" class="nav-btn" style="width:100%; margin-bottom: 16px;" onclick="genFetchAddresses()">获取优选列表</button>
        
        <div id="ipSubscriptionLinkBox" class="form-group hidden" style="display:none; gap:10px;">
            <input type="text" id="ipSubscriptionLink" readonly style="margin-bottom:0; color:#5a666d; background-color: #f8f9fa;">
            <button class="nav-btn" onclick="copyIpSubscriptionLink()" style="white-space: nowrap;">复制</button>
        </div>

        <textarea id="genAddressListInput" placeholder="点击上方按钮获取，或在此手动粘贴 IP 或 域名 列表..." rows="6"></textarea>
      </div>

      <div class="card">
        <h2>3. 生成结果</h2>
        <div id="generatedLinkBox" class="form-group hidden" style="display:none; gap:10px;">
           <label style="align-self:center; white-space:nowrap; margin-bottom:0; margin-right:5px;">订阅:</label>
           <input type="text" id="generatedConfigLink" readonly style="margin-bottom:0; color:#5a666d; background-color: #f8f9fa;">
           <button class="nav-btn" onclick="copyGeneratedLink()" style="white-space: nowrap;">复制</button>
        </div>
        <textarea id="genResultTextarea" readonly placeholder="点击下方“生成配置”按钮..." rows="8"></textarea>
      </div>

      <button id="genGenerateButton" class="nav-btn primary" style="width:100%; padding: 12px;" onclick="genGenerateConfigs()">生成配置</button>
      <button id="copyResultButton" class="nav-btn" style="width:100%; margin-top: 10px;" onclick="copyResults()">复制结果 (Base64)</button>

      <footer class="footer">
         <p>Powered by <a href="https://www.yangzihome.space">YZFN</a> | <a href="https://www.yangzihome.space/security.html">安全声明</a></p>
      </footer>
    </div>
  </div>

  <script>
    const WORKER_DOMAIN = "YOUR_WORKER_DOMAIN_PATH";
    const toastIcons = { success: '✅', error: '❌', info: 'ℹ️' };
    function showToast(msg, type='info') { const c = document.getElementById('toast-container'); const t = document.createElement('div'); t.className = 'toast'; t.innerHTML = \`<span>\${toastIcons[type]} \${msg}</span>\`; c.appendChild(t); setTimeout(()=>t.remove(), 5000); }
    function setButtonLoading(btn, ld, txt) { if(ld){ btn.disabled=true; btn.innerHTML='<span class="loader"></span>处理中...'; } else { btn.disabled=false; btn.innerHTML=txt; } }
    
    function toggleAddressOptions() {
        const type = document.querySelector('input[name="genAddressType"]:checked').value;
        const ipContainer = document.getElementById('ipOptionsContainer');
        const domainBox = document.getElementById('domainInfoBox');
        if (type === 'domain') {
            ipContainer.classList.add('hidden');
            domainBox.classList.remove('hidden');
        } else {
            ipContainer.classList.remove('hidden');
            domainBox.classList.add('hidden');
        }
    }

    // Tab switching for Config Source
    const sourceRadios = document.querySelectorAll('input[name="genConfigSource"]');
    sourceRadios.forEach(r => r.addEventListener('change', (e) => {
        if(e.target.value === 'uuid') {
            document.getElementById('genManualConfigInput').classList.add('hidden');
            document.getElementById('genUuidConfigInput').classList.remove('hidden');
        } else {
            document.getElementById('genManualConfigInput').classList.remove('hidden');
            document.getElementById('genUuidConfigInput').classList.add('hidden');
        }
    }));

    async function genFetchAddresses() {
        const btn = document.getElementById('genFetchBtn');
        const textarea = document.getElementById('genAddressListInput');
        const subBox = document.getElementById('ipSubscriptionLinkBox');
        const subInput = document.getElementById('ipSubscriptionLink');
        
        // Reset sub box
        subBox.style.display = 'none';
        subBox.classList.add('hidden');

        setButtonLoading(btn, true, '');
        
        try {
            const addrType = document.querySelector('input[name="genAddressType"]:checked').value;
            let url = \`\${WORKER_DOMAIN}/fetch-addresses?type=\${addrType}\`;
            
            if (addrType === 'ip') {
                const ipType = document.querySelector('input[name="genIpType"]:checked').value;
                const carrier = document.querySelector('input[name="genCarrierType"]:checked').value;
                url += \`&ipType=\${ipType}&carrierType=\${carrier}&source=database\`; // Always database
                
                // Show subscription link logic
                const subUrl = \`\${WORKER_DOMAIN}/batch-ip?type=ip&ipType=\${ipType}&carrier=\${carrier}\`;
                subInput.value = subUrl;
                subBox.style.display = 'flex';
                subBox.classList.remove('hidden');

            } else {
                // Domain subscription link
                 const subUrl = \`\${WORKER_DOMAIN}/batch-ip?type=domain\`;
                 subInput.value = subUrl;
                 subBox.style.display = 'flex';
                 subBox.classList.remove('hidden');
            }

            const res = await fetch(url);
            const data = await res.json();
            
            if (data.error) throw new Error(data.error);
            
            if (data.list && Array.isArray(data.list)) {
                textarea.value = data.list.join('\\n');
                showToast(data.message || \`获取成功: \${data.list.length} 条\`, 'success');
            } else {
                throw new Error("返回数据格式错误");
            }
        } catch (e) {
            showToast(e.message, 'error');
            textarea.value = "";
        } finally {
            setButtonLoading(btn, false, '获取优选列表');
        }
    }

    async function genGenerateConfigs() {
        const btn = document.getElementById('genGenerateButton');
        const resultArea = document.getElementById('genResultTextarea');
        const linkBox = document.getElementById('generatedLinkBox');
        const linkInput = document.getElementById('generatedConfigLink');

        // Reset
        linkBox.style.display = 'none';
        linkBox.classList.add('hidden');

        setButtonLoading(btn, true, '');

        try {
            const configSource = document.querySelector('input[name="genConfigSource"]:checked').value;
            const addressList = document.getElementById('genAddressListInput').value;
            
            let payload = { addressList };

            if (configSource === 'uuid') {
                const uuid = document.getElementById('genBaseConfigUuidInput').value.trim();
                if(!uuid) throw new Error("请输入 UUID");
                payload.baseConfigUuid = uuid;
                
                // Construct subscription link for UUID mode
                const addrType = document.querySelector('input[name="genAddressType"]:checked').value;
                let linkParams = \`type=\${addrType}\`;
                if(addrType === 'ip') {
                    const ipType = document.querySelector('input[name="genIpType"]:checked').value;
                    const carrier = document.querySelector('input[name="genCarrierType"]:checked').value;
                    linkParams += \`&ipType=\${ipType}&carrier=\${carrier}\`;
                }
                const subLink = \`\${WORKER_DOMAIN}/batch-configs/\${uuid}?\${linkParams}\`;
                linkInput.value = subLink;
                linkBox.style.display = 'flex';
                linkBox.classList.remove('hidden');

            } else {
                const manualConfig = document.getElementById('genBaseConfigInput').value.trim();
                if(!manualConfig) throw new Error("请输入基础配置");
                payload.baseConfig = manualConfig;
            }

            const res = await fetch(\`\${WORKER_DOMAIN}/generate\`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();

            if (data.error) throw new Error(data.error);

            if (data.configs && Array.isArray(data.configs)) {
                resultArea.value = data.configs.join('\\n');
                showToast(data.message || "生成成功", 'success');
            }
        } catch (e) {
            showToast(e.message, 'error');
        } finally {
            setButtonLoading(btn, false, '生成配置');
        }
    }

    function copyResults() {
        const content = document.getElementById('genResultTextarea').value;
        if (!content) return showToast('没有可复制的内容', 'error');
        const b64 = btoa(unescape(encodeURIComponent(content))); // utf-8 safe b64
        navigator.clipboard.writeText(b64).then(() => showToast('已复制 Base64 编码结果', 'success'));
    }
    
    function copyGeneratedLink() {
        const link = document.getElementById('generatedConfigLink').value;
        if(!link) return;
        navigator.clipboard.writeText(link).then(() => showToast('订阅链接已复制', 'success'));
    }

    function copyIpSubscriptionLink() {
        const link = document.getElementById('ipSubscriptionLink').value;
        if(!link) return;
        navigator.clipboard.writeText(link).then(() => showToast('列表地址已复制', 'success'));
    }
  </script>
</body>
</html>
`;