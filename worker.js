/* =================================================================
 *  Cloudflare Worker: All-in-One Proxy Tool (IP & Domain Optimization)
 *  Provides three functionalities:
 *  1. /                  - Batch Generator (Supports IPs & Domains).
 *  2. /manage            - Base Configuration Management.
 *  3. /batch-ip          - Direct Address fetching (IPs or Domains).
 *
 *  Shared D1 bindings:
 *  - 'DB' for 'configs' table (user proxy configs)
 *  - 'DB' for 'cfips' table (cached IP addresses)
 *  - 'DB' for 'cf_domains' table (optimization domains)
 * ================================================================= */

// =================================================================
//  GLOBAL UTILITIES (Shared by all functionalities)
// =================================================================

// Base64 UTILS for VMess
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
//  SECTION 1: Data Fetching (IPs & Domains)
// =================================================================

/**
 * 从 hostmonit.com API 获取IP。
 */
async function fetchIpsFromHostMonit() {
    const apiUrl = 'https://api.hostmonit.com/get_optimization_ip';
    console.log("正在从主 API (api.hostmonit.com) 获取优选IP...");

    const response = await fetch(apiUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'referer': 'https://stock.hostmonit.com/',
            'origin': 'https://stock.hostmonit.com',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
            'accept': 'application/json, text/plain, */*'
        },
        body: JSON.stringify({ key: "iDetkOys" })
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`主API请求失败: ${response.status} - ${errorText.substring(0, 200)}`);
    }

    const data = await response.json();

    if (data.code === 200 && data.info && Array.isArray(data.info)) {
        const ips = [];
        data.info.forEach(item => {
            if (item.ip && item.line) {
                const isV6 = item.ip.includes(':');
                ips.push({
                    ip: isV6 ? `[${item.ip}]` : item.ip,
                    ip_type: isV6 ? 'v6' : 'v4',
                    carrier: item.line,
                });
            }
        });
        return ips;
    } else {
        throw new Error(`主API响应格式不正确。`);
    }
}

/**
 * 从 vps789.com API 获取IP。
 */
async function fetchIpsFromVps789() {
    const apiUrl = 'https://vps789.com/openApi/cfIpApi';
    console.log("正在从备用 API (vps789.com) 获取优选IP...");

    const response = await fetch(apiUrl, {
        method: 'GET',
        headers: {
            'User-Agent': 'Cloudflare-Worker-Proxy-Tool/4.0',
            'Accept': 'application/json'
        }
    });

    if (!response.ok) {
        throw new Error(`备用API请求失败: ${response.status}`);
    }

    const data = await response.json();

    if (data.code === 0 && data.message === "true" && data.data) {
        const ips = [];
        const carrierGroups = data.data;

        for (const carrierKey in carrierGroups) {
            if (Object.prototype.hasOwnProperty.call(carrierGroups, carrierKey)) {
                const ipListForCarrier = carrierGroups[carrierKey];
                let currentCarrier;

                switch (carrierKey.toUpperCase()) {
                    case 'CT': currentCarrier = 'CT'; break;
                    case 'CU': currentCarrier = 'CU'; break;
                    case 'CM': currentCarrier = 'CM'; break;
                    case 'ALLAVG': currentCarrier = 'ALL'; break;
                    default: continue;
                }

                if (Array.isArray(ipListForCarrier)) {
                    ipListForCarrier.forEach(item => {
                        if (item.ip && typeof item.ip === 'string') {
                            const isV6 = item.ip.includes(':');
                            ips.push({
                                ip: isV6 ? `[${item.ip}]` : item.ip,
                                ip_type: isV6 ? 'v6' : 'v4',
                                carrier: currentCarrier,
                            });
                        }
                    });
                }
            }
        }
        return ips;
    } else {
        throw new Error(`备用API响应格式不正确。`);
    }
}

/**
 * 同时从两个API获取IP，合并并去重，然后存储到D1。
 */
async function fetchAndStoreIps(env) {
    let allFetchedIps = [];
    let apiFetchStatusMessages = [];
    let hasSuccessfulFetch = false;

    const results = await Promise.allSettled([
        fetchIpsFromHostMonit(),
        fetchIpsFromVps789()
    ]);

    results.forEach((result, index) => {
        const apiName = index === 0 ? '主API' : '备用API';
        if (result.status === 'fulfilled') {
            allFetchedIps.push(...result.value);
            apiFetchStatusMessages.push(`${apiName} 获取 ${result.value.length} 个`);
            hasSuccessfulFetch = true;
        } else {
            apiFetchStatusMessages.push(`${apiName} 失败`);
        }
    });

    if (!hasSuccessfulFetch) {
        return { success: false, error: `所有IP API均失败。详情: ${apiFetchStatusMessages.join('; ')}` };
    }

    const db = env.DB;
    if (!db) return { success: false, error: "D1 数据库未绑定。" };

    const uniqueIpsMap = new Map();
    allFetchedIps.forEach(ipInfo => {
        if (ipInfo && typeof ipInfo.ip === 'string' && ipInfo.ip.length > 0) {
            if (!uniqueIpsMap.has(ipInfo.ip)) {
                uniqueIpsMap.set(ipInfo.ip, ipInfo);
            }
        }
    });
    const uniqueNewIps = Array.from(uniqueIpsMap.values());

    if (uniqueNewIps.length === 0) {
        return { success: true, message: "无有效IP，保留旧数据。", count: 0 };
    }

    try {
        const statements = [
            db.prepare('DELETE FROM cfips'),
            ...uniqueNewIps.map(ipInfo =>
                db.prepare('INSERT INTO cfips (ip, ip_type, carrier, created_at) VALUES (?, ?, ?, ?)')
                .bind(ipInfo.ip, ipInfo.ip_type, ipInfo.carrier, Date.now())
            )
        ];

        await db.batch(statements);
        return { success: true, message: `成功存储 ${uniqueNewIps.length} 个IP。详情: ${apiFetchStatusMessages.join(' | ')}`, count: uniqueNewIps.length };
    } catch (dbError) {
        console.error("D1 Error:", dbError.message);
        return { success: false, error: `数据库操作失败: ${dbError.message}` };
    }
}

// 获取 IP
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

// [新增] 获取域名
async function fetchDomainsFromDB(env) {
    const db = env.DB;
    if (!db) throw new Error("D1 数据库未绑定。");
    // 对 cf_domains 表查询，请确保已建表
    try {
        const { results } = await db.prepare('SELECT domain FROM cf_domains ORDER BY created_at DESC').all();
        return results;
    } catch (e) {
        console.error("Fetching domains failed:", e.message);
        return [];
    }
}

// 统一的批量获取接口 (IP 或 域名)
async function handleGetBatchAddresses(url, env) {
    const type = url.searchParams.get('type') || 'ip'; // 'ip' or 'domain'

    try {
        let results = [];
        if (type === 'domain') {
            const domainData = await fetchDomainsFromDB(env);
            if (domainData.length === 0) {
                return new Response("Database is empty (no domains found in cf_domains).", { status: 404 });
            }
            const listText = domainData.map(item => item.domain).join('\n');
            return new Response(listText, { headers: { 'Content-Type': 'text/plain;charset=UTF-8' } });
        } else {
            // IP 逻辑
            const ipType = url.searchParams.get('ipType') || 'all';
            const carrier = url.searchParams.get('carrier') || 'all';
            const ipData = await fetchIpsFromDB(ipType, carrier, env);
            
            if (ipData.length === 0) {
                return new Response(`No IPs found for ipType=${ipType} and carrier=${carrier}.`, { status: 404 });
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

// 核心替换逻辑：支持 IP 和 域名
function replaceAddressesInConfigs(baseConfigsToProcess, addressList) {
    let generatedConfigs = [];
    // 用于提取原始地址 (IP或域名) 的正则
    const addressExtractionRegex = /@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9a-fA-F:\.]+\]|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?::\d+)?(?:[\/?#]|$)/;

    // 校验新地址是否合法的简单正则 (IP或域名)
    const validAddressRegex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9a-fA-F:\.]+\]|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})$/;

    for (const baseConfig of baseConfigsToProcess) {
        let configType = getProtocol(baseConfig);
        let processedBaseConfig;
        const pushError = (msg) => generatedConfigs.push(`[错误] ${msg}`);

        // 预处理配置并提取原始信息
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

        // 遍历所有新地址进行替换
        for (const newAddr of addressList) {
            // 如果地址带端口 (e.g. domain.com:443)，分离出 host
            let hostOnly = newAddr.includes(':') && !newAddr.includes('[') ? newAddr.split(':')[0] : newAddr;
            
            // IPv6特殊处理，如果是 [ffe::1]:443 这种格式暂时不做复杂分离，假设输入全是干净的 IP/Host
            // 这里为了安全，简单校验一下格式
            if (!validAddressRegex.test(newAddr) && !newAddr.includes(':')) {
                 // 如果完全不符合格式暂不强行报错，防止误杀复杂域名，但建议前端过滤
            }

            // 用于生成别名的地址字符串（去掉特殊字符）
            const cleanAddrForName = newAddr.replace(/[\[\]]/g, '');

            if (configType === 'trojan' || configType === 'vless') {
                try {
                    const url = new URL(processedBaseConfig);
                    const originalName = url.hash ? decodeURIComponent(url.hash.substring(1)) : `${configType}-node`;
                    const newName = `${originalName}-${cleanAddrForName}`;
                    url.hash = encodeURIComponent(newName);
                    
                    // 核心：替换 hostname (支持 IP 和 域名)
                    url.hostname = newAddr; 
                    
                    generatedConfigs.push(url.toString());
                } catch (e) {
                     pushError(`处理 ${configType} 出错: ${e.message}`);
                }
            } else if (configType === 'vmess') {
                const tempVmessObj = JSON.parse(JSON.stringify(processedBaseConfig));
                const originalName = tempVmessObj.ps || tempVmessObj.remark || 'vmess-node';
                tempVmessObj.ps = `${originalName}-${cleanAddrForName}`;
                tempVmessObj.add = newAddr; // 核心：替换地址
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

// 手动或UUID生成配置 (POST)
async function generateConfigs(request, env) {
    try {
        const body = await request.json();
        // 兼容旧参数 ipList，新参数统一叫 addressList
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
        
        // 使用新函数替换
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
// urlParams: type (ip/domain), ipType, carrier
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
//  SECTION 3: Base Configuration Management Logic
// =================================================================

function extractRemarkFromConfig(configStr, protocol) {
    try {
        if (protocol === 'vmess') {
            const decoded = b64_to_utf8(configStr.substring('vmess://'.length));
            const vmessObj = JSON.parse(decoded);
            return vmessObj.ps || vmessObj.remark || null;
        }
        if (protocol === 'vless' || protocol === 'trojan') {
            const url = new URL(configStr);
            if (url.hash) return decodeURIComponent(url.hash.substring(1));
        }
    } catch (e) { }
    return null;
}

async function handleAddConfig(request, env) {
    let body;
    try { body = await request.json(); } catch (e) { return jsonResponse({ error: '无效 JSON' }, 400); }

    const { uuid, config_data } = body;
    if (!uuid || !config_data) return jsonResponse({ error: '字段缺失' }, 400);

    const configLines = config_data.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    const statements = [];

    for (const line of configLines) {
        const protocol = getProtocol(line);
        if (protocol === 'unknown') continue;
        const remark = extractRemarkFromConfig(line, protocol);
        statements.push(
            env.DB.prepare('INSERT INTO configs (uuid, config_data, protocol, remark, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(uuid, config_data) DO NOTHING;')
            .bind(uuid, line, protocol, remark, Date.now(), Date.now())
        );
    }

    if (statements.length === 0) return jsonResponse({ error: '无有效配置' }, 400);

    await env.DB.batch(statements);
    return jsonResponse({ success: true, message: `成功处理 ${statements.length} 条。` }, 200);
}

async function handleGetConfigsByUuid(uuid, env) {
    const { results } = await env.DB.prepare('SELECT * FROM configs WHERE uuid = ? ORDER BY id ASC').bind(uuid).all();
    if (results && results.length > 0) return jsonResponse({ uuid: uuid, configs: results }, 200);
    return jsonResponse({ error: `Not Found` }, 404);
}

async function handleDeleteConfigsByUuid(uuid, env) {
    await env.DB.prepare('DELETE FROM configs WHERE uuid = ?').bind(uuid).run();
    return jsonResponse({ success: true, message: `Deleted` }, 200);
}

async function handleDeleteSingleConfig(id, env) {
    await env.DB.prepare('DELETE FROM configs WHERE id = ?').bind(id).run();
    return jsonResponse({ success: true, message: `Deleted` });
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

        const manageUUID = new URLPattern({ pathname: '/manage/configs/:uuid' });
        const manageID = new URLPattern({ pathname: '/manage/configs/id/:id' });
        const batchUUID = new URLPattern({ pathname: '/batch-configs/:uuid' });

        try {
            if (method === 'GET') {
                if (path === '/') {
                    return new Response(generatePageHtmlContent.replace(/YOUR_WORKER_DOMAIN_PATH/g, DOMAIN_NAME), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
                }
                if (path === '/manage') {
                    return new Response(managePageHtmlContent.replace(/YOUR_WORKER_DOMAIN_PATH/g, DOMAIN_NAME), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
                }
                // 获取 IP/域名 列表文本
                if (path === '/batch-ip') {
                    return await handleGetBatchAddresses(url, env);
                }
                // 订阅地址
                const batchMatch = batchUUID.exec(url);
                if (batchMatch) {
                    return await handleGetBatchConfigs(batchMatch.pathname.groups.uuid, url.searchParams, env);
                }
                // 前端专用获取接口 (返回JSON)
                if (path === '/fetch-addresses') {
                    const type = url.searchParams.get('type') || 'ip';
                    if (type === 'domain') {
                        const domains = await fetchDomainsFromDB(env);
                        return jsonResponse({ list: domains.map(d => d.domain), message: `获取到 ${domains.length} 个域名` });
                    } else {
                        // IP 逻辑
                        const ipSource = url.searchParams.get('source') || 'database';
                        if (ipSource === 'api') {
                            const res = await fetchAndStoreIps(env);
                            if(!res.success) return jsonResponse({ error: res.error }, 200);
                        }
                        const ips = await fetchIpsFromDB(
                            url.searchParams.get('ipType') || 'all',
                            url.searchParams.get('carrierType') || 'all',
                            env
                        );
                        return jsonResponse({ list: ips.map(i => i.ip), message: `获取到 ${ips.length} 个IP` }); 
                    }
                }
                // 兼容旧接口
                if (path === '/fetch-ips') {
                    // Redirect logic internally
                     const ipSource = url.searchParams.get('source') || 'database';
                     if (ipSource === 'api') await fetchAndStoreIps(env);
                     const ips = await fetchIpsFromDB(url.searchParams.get('ipType') || 'all', url.searchParams.get('carrierType') || 'all', env);
                     return jsonResponse({ ips: ips.map(i => i.ip), message: `Success` });
                }

                const uuidMatch = manageUUID.exec(url);
                if (uuidMatch) return await handleGetConfigsByUuid(uuidMatch.pathname.groups.uuid, env);
            }

            if (method === 'POST') {
                if (path === '/generate') return generateConfigs(request, env);
                if (path === '/manage/configs') return await handleAddConfig(request, env);
            }

            if (method === 'DELETE') {
                const idMatch = manageID.exec(url);
                if (idMatch) return await handleDeleteSingleConfig(idMatch.pathname.groups.id, env);
                const uuidMatch = manageUUID.exec(url);
                if (uuidMatch) return await handleDeleteConfigsByUuid(uuidMatch.pathname.groups.uuid, env);
            }

            return new Response('404 Not Found', { status: 404 });
        } catch (err) {
            return new Response("Internal Error: " + err.message, { status: 500 });
        }
    },

    async scheduled(controller, env, ctx) {
        ctx.waitUntil(fetchAndStoreIps(env));
    }
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
.nav-btn { padding: 8px 16px; text-align: center; background: #E8EBED; border: 2px solid #89949B; border-radius: 4px; color: #5a666d; text-decoration: none; font-weight: 500; font-size: 0.95rem; transition: all 0.3s; white-space: nowrap; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; }
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
.info-box, .config-link-box { background-color: #e8ebed; color: #5a666d; border-left: 4px solid #89949B; padding: 12px 16px; border-radius: 4px; font-size: 0.85rem; text-align: left; line-height: 1.5; margin: 16px 0; }
.info-box a, .config-link-box a { color: #3d474d; font-weight: bold; text-decoration: none; word-break: break-all; }
.info-box a:hover, .config-link-box a:hover { text-decoration: underline; }
.config-link-box button { padding: 4px 8px; font-size: 0.8rem; height: auto; border-radius: 3px; margin-left:10px; vertical-align: middle;}
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
@media (max-width: 768px) { html { font-size: 100%; } .container { padding: 20px 15px; justify-content: flex-start; } .profile-name { font-size: 1.8rem; } .profile-quote { font-size: 0.95rem; margin-bottom: 20px; } .card { padding: 20px 15px; margin-bottom: 20px; } .card h2 { font-size: 1.3rem; } .nav-btn { padding: 9px 12px; font-size: 0.9rem; } .table-container th, .table-container td { padding: 8px 10px; font-size: 0.8rem; } .config-data-cell { max-width: 150px; } #toast-container { top: 10px; left: 10px; right: 10px; width: auto; transform: translateX(0); align-items: center; } .toast { width: 100%; max-width: 400px; animation: slideDown 0.5s forwards, fadeOut 0.5s 4.5s forwards; } @keyframes slideDown { from { opacity: 0; transform: translateY(-100%); } to { opacity: 1; transform: translateY(0); } } @keyframes fadeOut { from { opacity: 1; } to { opacity: 0; transform: translateY(-20px); } } }
`;

const generatePageHtmlContent = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="https://s3.yangzifun.org/logo.ico" type="image/x-icon">
  <title>YZFN 优选配置生成 (Pro)</title>
  <style>${newGlobalStyle}</style>
</head>
<body>
  <div id="toast-container"></div>
  <div class="container">
    <div class="content-group">
      <h1 class="profile-name">CF优选配置批量生成</h1>
      <p class="profile-quote">支持 IP 优选与域名优选的批量替换工具</p>

      <div class="nav-grid">
        <a href="/" class="nav-btn primary">批量生成</a>
        <a href="/manage" class="nav-btn">配置管理</a>
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
            <div class="info-box">在 <a href="/manage" target="_blank">配置管理</a> 页面添加和管理UUID。</div>
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
             <div class="form-group">
                <label>数据来源</label>
                <div class="radio-group">
                    <label><input type="radio" name="genIpSource" value="database" checked><span>从本地数据库</span></label>
                    <label><input type="radio" name="genIpSource" value="api"><span>从远程API更新</span></label>
                </div>
            </div>
        </div>

        <div id="domainInfoBox" class="info-box hidden">
           将使用数据库中存储的 Cloudflare 优选域名列表进行替换。
        </div>

        <button id="genFetchBtn" class="nav-btn" style="width:100%; margin-bottom: 16px;" onclick="genFetchAddresses()">获取优选列表</button>

        <div id="ipSubscriptionLinkBox" class="config-link-box hidden">
            <strong>列表订阅:</strong> <a id="ipSubscriptionLink" href="#" target="_blank"></a>
            <button class="nav-btn" onclick="copyIpSubscriptionLink()">复制</button>
        </div>

        <textarea id="genAddressListInput" placeholder="点击上方按钮获取，或在此手动粘贴 IP 或 域名 列表..." rows="6"></textarea>
      </div>

      <div class="card">
        <h2>3. 生成结果</h2>
        <div id="generatedLinkBox" class="config-link-box hidden">
          <strong>节点订阅链接:</strong> <a id="generatedConfigLink" href="#" target="_blank"></a>
          <button class="nav-btn" onclick="copyGeneratedLink()">复制</button>
        </div>
        <textarea id="genResultTextarea" readonly placeholder="点击下方“生成配置”按钮..." rows="8"></textarea>
      </div>

      <button id="genGenerateButton" class="nav-btn primary" style="width:100%; padding: 12px;" onclick="genGenerateConfigs()">生成配置</button>
      <button id="copyResultButton" class="nav-btn" style="width:100%; margin-top: 10px;" onclick="copyResults()">复制结果 (Base64)</button>

      <footer class="footer">
        <p>Powered by YZFN</p>
      </footer>
    </div>
  </div>

  <script>
    const WORKER_DOMAIN = "YOUR_WORKER_DOMAIN_PATH";
    const toastIcons = { success: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm-1.293-6.293a1 1 0 011.414 0L12 13.414l2.879-2.88a1 1 0 111.414 1.415l-3.586 3.586a1 1 0 01-1.414 0L8.707 13.121a1 1 0 010-1.414z" clip-rule="evenodd" /></svg>', error: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" /></svg>', info: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" /></svg>' };
    function showToast(msg, type='info') { const c = document.getElementById('toast-container'); const t = document.createElement('div'); t.className = 'toast'; t.innerHTML = \`\${toastIcons[type]}<span>\${msg}</span>\`; c.appendChild(t); setTimeout(()=>t.remove(), 5000); }
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

    function toggleGenConfigSource() {
        const isManual = document.querySelector('input[name="genConfigSource"]:checked').value === 'manual';
        document.getElementById('genManualConfigInput').classList.toggle('hidden', !isManual);
        document.getElementById('genUuidConfigInput').classList.toggle('hidden', isManual);
        document.getElementById('generatedLinkBox').classList.add('hidden');
    }

    async function genFetchAddresses() {
        const btn = document.getElementById('genFetchBtn');
        const orgTxt = btn.innerHTML;
        setButtonLoading(btn, true, orgTxt);
        const listInput = document.getElementById('genAddressListInput');
        const subBox = document.getElementById('ipSubscriptionLinkBox');
        const subLink = document.getElementById('ipSubscriptionLink');
        
        listInput.value = '';
        subBox.classList.add('hidden');

        const addrType = document.querySelector('input[name="genAddressType"]:checked').value;
        
        let subUrl = \`\${WORKER_DOMAIN}/batch-ip?type=\${addrType}\`;
        let fetchUrl = \`/fetch-addresses?type=\${addrType}\`;

        if (addrType === 'ip') {
             const ipType = document.querySelector('input[name="genIpType"]:checked').value;
             const carrier = document.querySelector('input[name="genCarrierType"]:checked').value;
             const src = document.querySelector('input[name="genIpSource"]:checked').value;
             subUrl += \`&ipType=\${encodeURIComponent(ipType)}&carrier=\${encodeURIComponent(carrier)}\`;
             fetchUrl += \`&ipType=\${encodeURIComponent(ipType)}&carrierType=\${encodeURIComponent(carrier)}&source=\${src}\`;
        }

        subLink.href = subUrl;
        subLink.textContent = subUrl;
        subBox.classList.remove('hidden');

        try {
            const res = await fetch(fetchUrl);
            const data = await res.json();
            if(data.error) throw new Error(data.error);
            if(data.list && data.list.length > 0) {
                listInput.value = data.list.join('\\n');
                showToast(data.message || \`获取到 \${data.list.length} 条数据\`, 'success');
            } else {
                showToast('未找到数据', 'info');
            }
        } catch(e) { showToast(e.message, 'error'); }
        finally { setButtonLoading(btn, false, orgTxt); }
    }

    async function genGenerateConfigs() {
        const btn = document.getElementById('genGenerateButton');
        const orgTxt = btn.innerHTML;
        setButtonLoading(btn, true, orgTxt);
        const resArea = document.getElementById('genResultTextarea');
        const genLinkBox = document.getElementById('generatedLinkBox');
        const genLink = document.getElementById('generatedConfigLink');
        
        resArea.value = '';
        genLinkBox.classList.add('hidden');

        const source = document.querySelector('input[name="genConfigSource"]:checked').value;
        const addrType = document.querySelector('input[name="genAddressType"]:checked').value;
        const addressList = document.getElementById('genAddressListInput').value;

        const body = { addressList };
        let uuid = '';

        if(source === 'manual') body.baseConfig = document.getElementById('genBaseConfigInput').value;
        else {
             uuid = document.getElementById('genBaseConfigUuidInput').value.trim();
             body.baseConfigUuid = uuid;
        }

        if ((!body.baseConfig && !body.baseConfigUuid) || !body.addressList) {
            showToast('参数不完整', 'error'); setButtonLoading(btn, false, orgTxt); return;
        }

        try {
            const res = await fetch('/generate', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
            const data = await res.json();
            if(data.error) throw new Error(data.error);

            resArea.value = data.configs.join('\\n');
            const validCount = data.configs.filter(c=>!c.startsWith('[错误]')).length;
            showToast(\`成功生成 \${validCount} 条\`, 'success');

            if(source === 'uuid' && uuid && validCount > 0) {
                let linkUrl = \`\${WORKER_DOMAIN}/batch-configs/\${uuid}?type=\${addrType}\`;
                if(addrType === 'ip') {
                    const ipType = document.querySelector('input[name="genIpType"]:checked').value;
                    const carrier = document.querySelector('input[name="genCarrierType"]:checked').value;
                    linkUrl += \`&ipType=\${encodeURIComponent(ipType)}&carrier=\${encodeURIComponent(carrier)}\`;
                }
                genLink.href = linkUrl;
                genLink.textContent = linkUrl;
                genLinkBox.classList.remove('hidden');
            }
        } catch(e) { showToast(e.message, 'error'); resArea.value = '错误:\\n' + e.message; }
        finally { setButtonLoading(btn, false, orgTxt); }
    }

    function copyResults() {
        const v = document.getElementById('genResultTextarea').value;
        if(!v) return;
        const c = v.split('\\n').filter(l => !l.startsWith('[错误]')).join('\\n');
        navigator.clipboard.writeText(btoa(c)).then(()=>showToast('已复制Base64', 'success'), ()=>showToast('复制失败','error'));
    }
    function copyGeneratedLink() { navigator.clipboard.writeText(document.getElementById('generatedConfigLink').href).then(()=>showToast('链接已复制','success')); }
    function copyIpSubscriptionLink() { navigator.clipboard.writeText(document.getElementById('ipSubscriptionLink').href).then(()=>showToast('链接已复制','success')); }

    document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('input[name="genConfigSource"]').forEach(r => r.addEventListener('change', toggleGenConfigSource));
        toggleGenConfigSource();
        toggleAddressOptions();
    });
  </script>
</body>
</html>
`;

const managePageHtmlContent = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="https://s3.yangzifun.org/logo.ico" type="image/x-icon">
  <title>基础配置管理器</title>
  <style>${newGlobalStyle}
    .table-container { overflow-x: auto; border: 2px solid #89949B; border-radius: 4px; background: #fff; margin-top:20px;}
    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th, td { padding: 10px 14px; text-align: left; border-bottom: 2px solid #E8EBED; white-space: nowrap; }
    th { font-weight: bold; color: #3d474d; background-color: #f0f2f5; }
    tr:last-child td { border-bottom: none; }
    .config-data-cell { white-space: normal; word-break: break-all; max-width: 300px;}
    .actions-cell button { margin-right: 5px; }
    .placeholder { padding: 40px; text-align: center; color: #89949B; }
  </style>
</head>
<body>
  <div id="toast-container"></div>
  <div class="container">
    <div class="content-group">
      <h1 class="profile-name">基础配置管理器</h1>
      <p class="profile-quote">在这里添加、查询和删除用于批量生成的基础配置</p>

      <div class="nav-grid">
        <a href="/" class="nav-btn">批量生成</a>
        <a href="/manage" class="nav-btn primary">配置管理</a>
      </div>

      <div class="card">
        <h2>1. 操作指定 UUID</h2>
        <div class="form-group">
            <label for="queryUuidInput">输入要操作的 UUID</label>
            <input type="text" id="queryUuidInput" placeholder="例如: my-home-configs">
        </div>
        <div class="nav-grid" style="justify-content: flex-start;">
            <button id="queryBtn" class="nav-btn primary" onclick="manageQueryByUuid()">查询配置</button>
            <button id="deleteBtn" class="nav-btn" onclick="manageDeleteGroupdByUuid()">删除所有</button>
        </div>
      </div>

      <div class="card">
        <h2>2. 查询结果</h2>
        <div id="queryResultsContainer">
            <p class="placeholder">请输入一个 UUID 并点击查询。</p>
        </div>
      </div>

      <div class="card">
        <h2>3. 批量添加配置</h2>
        <form id="manageConfigForm" onsubmit="event.preventDefault(); manageAddConfig();">
            <div class="form-group">
              <label for="addUuidInput">目标 UUID</label>
              <input type="text" id="addUuidInput" placeholder="将配置添加到哪个 UUID" required>
            </div>
            <div class="form-group">
                <label for="addConfigData">配置数据 (每行一个链接)</label>
                <textarea id="addConfigData" required placeholder="vmess://...\\nvless://...\\ntrojan://..." rows="6"></textarea>
            </div>
            <button type="submit" id="addConfigBtn" class="nav-btn primary" style="width: auto;">确认批量添加</button>
        </form>
      </div>
      <footer class="footer"><p>Powered by YZFN</p></footer>
    </div>
  </div>

  <script>
    const toastIcons = { success: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm-1.293-6.293a1 1 0 011.414 0L12 13.414l2.879-2.88a1 1 0 111.414 1.415l-3.586 3.586a1 1 0 01-1.414 0L8.707 13.121a1 1 0 010-1.414z" clip-rule="evenodd" /></svg>', error: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" /></svg>', info: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" /></svg>' };
    function showToast(message, type = 'info') { const container = document.getElementById('toast-container'); const toast = document.createElement('div'); toast.className = 'toast'; toast.innerHTML = \`\${toastIcons[type]}<span>\${message}</span>\`; container.appendChild(toast); setTimeout(() => toast.remove(), 5000); }
    function setButtonLoading(button, isLoading, originalText = '') { if (isLoading) { button.disabled = true; button.dataset.originalText = button.innerHTML; button.innerHTML = '<span class="loader"></span>处理中...'; } else { button.disabled = false; button.innerHTML = originalText || button.dataset.originalText; } }
    async function manageQueryByUuid() {
        const button = document.getElementById('queryBtn'); setButtonLoading(button, true);
        const uuid = document.getElementById('queryUuidInput').value.trim();
        const resultsContainer = document.getElementById('queryResultsContainer');
        if (!uuid) { showToast('请输入要查询的UUID。', 'error'); setButtonLoading(button, false); return; }
        try {
            const response = await fetch(\`/manage/configs/\${uuid}\`);
            const data = await response.json();
            document.getElementById('addUuidInput').value = uuid;
            if (response.status === 404) { resultsContainer.innerHTML = '<p class="placeholder">未找到此 UUID 的配置。</p>'; showToast('未找到配置。', 'info'); return; }
            if (data.configs && data.configs.length > 0) {
                let tableHtml = '<div class="table-container"><table><thead><tr><th>ID</th><th>备注</th><th>协议</th><th class="config-data-cell">配置数据</th><th class="actions-cell">操作</th></tr></thead><tbody>';
                data.configs.forEach(config => { tableHtml += \`<tr><td>\${config.id}</td><td>\${config.remark || '---'}</td><td>\${config.protocol}</td><td class="config-data-cell" title="\${config.config_data}">\${config.config_data}</td><td class="actions-cell"><button class="nav-btn" style="background-color:#d44" onclick="manageDeleteSingleConfig(event, \${config.id})">删除</button></td></tr>\`; });
                tableHtml += '</tbody></table></div>'; resultsContainer.innerHTML = tableHtml; showToast(\`查询到 \${data.configs.length} 条配置。\`, 'success');
            } else { resultsContainer.innerHTML = '<p class="placeholder">没有配置。</p>'; }
        } catch (error) { resultsContainer.innerHTML = \`<p class="placeholder" style="color:red;">查询失败: \${error.message}</p>\`; showToast(error.message, 'error'); } finally { setButtonLoading(button, false); }
    }
    async function manageAddConfig() {
      const button = document.getElementById('addConfigBtn'); setButtonLoading(button, true);
      const uuid = document.getElementById('addUuidInput').value.trim(); const config_data = document.getElementById('addConfigData').value.trim();
      try {
        if (!uuid || !config_data) throw new Error("不能为空");
        await fetch('/manage/configs', { method: 'POST', header:{'Content-Type':'application/json'}, body: JSON.stringify({ uuid, config_data }) });
        showToast('添加成功', 'success'); document.getElementById('addConfigData').value = '';
        if (uuid === document.getElementById('queryUuidInput').value.trim()) await manageQueryByUuid();
      } catch (error) { showToast(error.message, 'error'); } finally { setButtonLoading(button, false); }
    }
    async function manageDeleteGroupdByUuid() {
        if (!confirm(\`确定删除所有配置吗？\`)) return;
        const button = document.getElementById('deleteBtn'); setButtonLoading(button, true);
        const uuid = document.getElementById('queryUuidInput').value.trim();
        try { await fetch(\`/manage/configs/\${uuid}\`, { method: 'DELETE' }); showToast('删除成功', 'success'); manageQueryByUuid(); } catch(e) { showToast(e.message, 'error'); } finally { setButtonLoading(button, false); }
    }
    async function manageDeleteSingleConfig(event, configId) {
        if (!confirm(\`确定删除 ID \${configId} 吗？\`)) return;
        const button = event.currentTarget; setButtonLoading(button, true);
        try { await fetch(\`/manage/configs/id/\${configId}\`, { method: 'DELETE' }); showToast('删除成功', 'success'); manageQueryByUuid(); } catch (e) { showToast(e.message, 'error'); setButtonLoading(button, false); }
    }
  </script>
</body>
</html>
`;
