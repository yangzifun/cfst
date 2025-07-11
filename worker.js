/* =================================================================
 *  Cloudflare Worker: All-in-One Proxy Tool (IP Replacement & Config Management)
 *  Provides three functionalities:
 *  1. /                  - IP Replacement Batch Generator with modern UI/UX.
 *  2. /manage            - Base Configuration Management with BATCH ADD and robust single-entry deletion.
 *  3. /batch-ip          - Direct IP fetching via GET request (e.g., /batch-ip?ipType=v4&carrier=CT).
 *
 *  Shared D1 bindings:
 *  - 'DB' for 'configs' table (config management data)
 *  - 'DB' for 'ips' table (cached IP addresses)
 * 
 *  VERSION: 3.2 (Fixed a typo in the subscription link handler causing Error 1101)
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
//  SECTION 1: IP Replacement & Batch Generation Logic
// =================================================================

async function fetchAndStoreIps(env) {
    const apiUrl = 'https://api.vvhan.com/tool/cf_ip';
    let newIps = [];

    try {
        console.log("Fetching IPs from external API...");
        const response = await fetch(apiUrl, {
            headers: {
                'User-Agent': 'Cloudflare-Worker-Proxy-Tool/3.2',
                'Accept': 'application/json',
                'Origin': 'https://cf.vvhan.com',
                'Referer': 'https://cf.vvhan.com/',
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`API请求失败: ${response.status} ${response.statusText} - ${errorText.substring(0, 200)}`);
        }

        const data = await response.json();
        if (data.success && data.data) {
            const processIpData = (ipData, type, carrierCode) => {
                if (ipData && Array.isArray(ipData)) {
                    ipData.forEach(item => {
                        if (item.ip) {
                            newIps.push({
                                ip: type === 'v6' ? `[${item.ip}]` : item.ip,
                                ip_type: type,
                                carrier: carrierCode,
                            });
                        }
                    });
                }
            };

            if (data.data.v4) {
                if (data.data.v4.CM) processIpData(data.data.v4.CM, 'v4', 'CM');
                if (data.data.v4.CU) processIpData(data.data.v4.CU, 'v4', 'CU');
                if (data.data.v4.CT) processIpData(data.data.v4.CT, 'v4', 'CT');
            }
            if (data.data.v6) {
                if (data.data.v6.CM) processIpData(data.data.v6.CM, 'v6', 'CM');
                if (data.data.v6.CU) processIpData(data.data.v6.CU, 'v6', 'CU');
                if (data.data.v6.CT) processIpData(data.data.v6.CT, 'v6', 'CT');
            }
        } else {
            throw new Error('API 响应格式不正确或未成功。');
        }

        const db = env.DB;
        if (!db) {
            return { success: false, error: "D1 数据库绑定 'DB' 未找到。" };
        }

        console.log(`清空并插入 ${newIps.length} 个新IP到 D1...`);
        const statements = [
            db.prepare('DELETE FROM ips'),
            ...newIps.map(ipInfo =>
                db.prepare('INSERT INTO ips (ip, ip_type, carrier, created_at) VALUES (?, ?, ?, ?)')
                .bind(ipInfo.ip, ipInfo.ip_type, ipInfo.carrier, Date.now())
            )
        ];
        await db.batch(statements);
        console.log(`成功获取并存储了 ${newIps.length} 个IP。`);
        return { success: true, message: `成功从接口获取并存储了 ${newIps.length} 个IP。`, count: newIps.length };

    } catch (e) {
        console.error("IP获取和存储过程中发生错误:", e.message);
        return { success: false, error: e.message };
    }
}

async function fetchIpsFromDB(ipType, carrierType, env) {
    const db = env.DB;
    if (!db) {
        throw new Error("D1 数据库未绑定或不可用。");
    }
  
    let query = 'SELECT ip, ip_type, carrier FROM ips WHERE 1=1'; 
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

    try {
        const { results } = await db.prepare(query).bind(...params).all();
        return results; 
    } catch (e) {
        console.error("从D1获取IP时出错:", e.message);
        throw new Error("数据库查询失败: " + e.message);
    }
}

async function handleGetBatchIps(url, env) {
    const ipType = url.searchParams.get('ipType') || 'all';
    const carrier = url.searchParams.get('carrier') || 'all';

    try {
        const ipsData = await fetchIpsFromDB(ipType, carrier, env);

        if (ipsData.length === 0) {
            return new Response(`No IPs found for ipType=${ipType} and carrier=${carrier}. Your database might be empty or the criteria matched no entries.`, {
                status: 404,
                headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
            });
        }

        const ipListText = ipsData.map(item => item.ip).join('\n');

        return new Response(ipListText, {
            status: 200,
            headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
        });

    } catch (e) {
        console.error("Error in /batch-ip handler:", e.message);
        return new Response("An internal server error occurred while fetching IPs: " + e.message, {
            status: 500,
            headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
        });
    }
}

async function fetchConfigsByUuidFromDB(uuid, env) {
    const db = env.DB;
    if (!db) {
        console.error("D1 database binding 'DB' not found in env for config fetch.");
        return [];
    }
    try {
        const stmt = db.prepare('SELECT config_data FROM configs WHERE uuid = ? ORDER BY id ASC');
        const { results } = await stmt.bind(uuid).all();
        return results.map(row => row.config_data);
    } catch (e) {
        console.error(`Error fetching configs for UUID ${uuid} from D1:`, e.message);
        return [];
    }
}

function replaceIpsInConfigs(baseConfigsToProcess, ipList) {
    let generatedConfigs = [];
    const addressExtractionRegex = /@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9a-fA-F:\.]+\]|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?::\d+)?(?:[\/?#]|$)/;

    for (const baseConfig of baseConfigsToProcess) {
        let originalAddress = '';
        let configType = getProtocol(baseConfig);
        let processedBaseConfig;
        const pushError = (msg) => generatedConfigs.push(`[错误] ${msg}`);

        switch (configType) {
            case 'trojan':
            case 'vless':
                const addressMatch = baseConfig.match(addressExtractionRegex);
                if (!addressMatch) {
                    pushError(`配置 "${baseConfig.substring(0, Math.min(baseConfig.length, 30))}..." 中未找到地址(IP或域名)，已跳过。`);
                    continue;
                }
                originalAddress = addressMatch[1];
                processedBaseConfig = baseConfig;
                break;
            case 'vmess':
                const encodedJson = baseConfig.substring('vmess://'.length);
                try {
                    let vmessObj = JSON.parse(b64_to_utf8(encodedJson));
                    if (!vmessObj.add) {
                        pushError(`VMess配置中未找到 "add" 字段 (地址)，已跳过。`);
                        continue;
                    }
                    originalAddress = vmessObj.add;
                    processedBaseConfig = vmessObj;
                } catch (e) {
                    pushError(`VMess配置解码或解析失败: ${e.message}，已跳过。`);
                    continue;
                }
                break;
            default:
                pushError(`不支持的配置类型 "${baseConfig.substring(0, Math.min(baseConfig.length, 30))}..."，已跳过。`);
                continue;
        }

        for (const newIp of ipList) {
            if (!/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9a-fA-F:\.]+\])$/.test(newIp)) {
                pushError(`无效的IP格式 "${newIp}"，跳过替换。`);
                continue;
            }

            const cleanedIpForName = newIp.replace(/[\[\]]/g, '');

            if (configType === 'trojan' || configType === 'vless') {
                try {
                    const url = new URL(processedBaseConfig);
                    const originalName = url.hash ? decodeURIComponent(url.hash.substring(1)) : `${configType}-node`;
                    const newName = `${originalName}-${cleanedIpForName}`;
                    url.hash = encodeURIComponent(newName);
                    url.hostname = newIp;
                    generatedConfigs.push(url.toString());
                } catch (e) {
                     pushError(`为IP "${newIp}" 处理 ${configType} 链接时出错: ${e.message}`);
                }
            } else if (configType === 'vmess') {
                const tempVmessObj = JSON.parse(JSON.stringify(processedBaseConfig));
                const originalName = tempVmessObj.ps || tempVmessObj.remark || 'vmess-node';
                tempVmessObj.ps = `${originalName}-${cleanedIpForName}`;
                tempVmessObj.add = newIp;
                if (tempVmessObj.remark) {
                    delete tempVmessObj.remark;
                }
              
                try {
                    generatedConfigs.push(`vmess://${utf8_to_b64(JSON.stringify(tempVmessObj))}`);
                } catch (e) {
                    pushError(`无法为IP "${newIp}" 重新编码VMess配置: ${e.message}`);
                }
            }
        }
    }
    return generatedConfigs;
}

async function generateConfigs(request, env) {
    try {
        const data = await request.json();
        const { ipList: ipListText, baseConfigUuid, baseConfig: baseConfigFromRequest } = data;
        let baseConfigsToProcess = [];

        if (baseConfigUuid) {
            const configsFromDb = await fetchConfigsByUuidFromDB(baseConfigUuid, env);
            if (configsFromDb.length === 0) {
                return jsonResponse({ error: `未找到 UUID 为 "${baseConfigUuid}" 的任何基础配置。` }, 404);
            }
            baseConfigsToProcess = configsFromDb;
        } else if (baseConfigFromRequest) {
            baseConfigsToProcess = baseConfigFromRequest.split('\n').map(s => s.trim()).filter(Boolean);
            if (baseConfigsToProcess.length === 0) {
                 return jsonResponse({ error: "手动输入的基础配置不能为空。" }, 400);
            }
        } else {
            return jsonResponse({ error: "必须提供基础配置或基础配置的UUID。" }, 400);
        }

        if (!ipListText || ipListText.trim() === '') {
            return jsonResponse({ error: "IP 列表不能为空。" }, 400);
        }

        const ipList = ipListText.split('\n').map(ip => ip.trim()).filter(ip => ip.length > 0);
        if (ipList.length === 0) {
            return jsonResponse({ error: "IP 列表不能为空或格式无效。" }, 400);
        }

        const generatedConfigs = replaceIpsInConfigs(baseConfigsToProcess, ipList);
      
        const successCount = generatedConfigs.filter(c => !c.startsWith('[错误]')).length;
        const errorCount = generatedConfigs.length - successCount;
        let message = `生成完成！成功 ${successCount} 条`
        if(errorCount > 0){
            message += `，失败 ${errorCount} 条。`
        } else {
            message += `。`
        }
        return jsonResponse({ configs: generatedConfigs, message: message });
    } catch (e) {
        console.error("生成配置时出错:", e.message);
        return jsonResponse({ error: "处理请求时发生内部错误: " + e.message }, 500);
    }
}

async function handleGetBatchConfigs(uuid, ipType, carrier, env) {
    if (!uuid) {
        return jsonResponse({ error: 'UUID 参数为必填项。' }, 400);
    }
  
    const baseConfigs = await fetchConfigsByUuidFromDB(uuid, env);
    if (baseConfigs.length === 0) {
        return jsonResponse({ error: `未找到 UUID 为 "${uuid}" 的基础配置。` }, 404);
    }

    let ipsData;
    try {
        ipsData = await fetchIpsFromDB(ipType, carrier, env);
    } catch (e) {
        console.error("Error fetching IPs for batch config:", e);
        return jsonResponse({ error: "获取IP列表失败: " + e.message }, 500);
    }
  
    if (ipsData.length === 0) {
        return jsonResponse({ error: `未找到符合 IP 类型 "${ipType}" 和运营商 "${carrier}" 的IP地址。` }, 404);
    }
    const ipList = ipsData.map(item => item.ip);

    const generatedConfigs = replaceIpsInConfigs(baseConfigs, ipList);

    const filteredConfigs = generatedConfigs.filter(c => !c.startsWith('[错误]'));

    if (filteredConfigs.length === 0) {
        return new Response("No valid configurations could be generated with the provided parameters.", {
            status: 400,
            headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
        });
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
//  SECTION 2: Base Configuration Management Logic
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
            if (url.hash) {
                return decodeURIComponent(url.hash.substring(1));
            }
        }
    } catch (e) {
        console.warn(`Could not extract remark from config "${configStr.substring(0,30)}...": ${e.message}`);
        return null;
    }
    return null;
}

async function handleAddConfig(request, env) {
    let body;
    try {
        body = await request.json();
    } catch (e) {
        return jsonResponse({ error: '无效的 JSON 请求体' }, 400);
    }

    const { uuid, config_data } = body;
    if (!uuid || !config_data) {
        return jsonResponse({ error: '`uuid` 和 `config_data` 字段为必填项。' }, 400);
    }

    const configLines = config_data.split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0);

    if (configLines.length === 0) {
        return jsonResponse({ error: '未提供任何有效的配置链接。' }, 400);
    }

    const statements = [];
    let invalidCount = 0;

    for (const line of configLines) {
        const protocol = getProtocol(line);
        if (protocol === 'unknown') {
            invalidCount++;
            continue;
        }
        const remark = extractRemarkFromConfig(line, protocol);
      
        statements.push(
            env.DB.prepare(
                'INSERT INTO configs (uuid, config_data, protocol, remark, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(uuid, config_data) DO NOTHING;'
            ).bind(uuid, line, protocol, remark, Date.now(), Date.now())
        );
    }
  
    if (statements.length === 0) {
        return jsonResponse({ error: `提交的所有 ${invalidCount} 行均为无效格式。` }, 400);
    }

    try {
        const results = await env.DB.batch(statements);
        const newInserts = results.reduce((acc, res) => acc + (res.changes || 0), 0);
      
        let message = `成功处理 ${statements.length} 条有效配置。`;
        if (newInserts > 0) {
            message += ` 新增 ${newInserts} 条。`;
        }
        const skipped = statements.length - newInserts;
        if (skipped > 0){
             message += ` ${skipped} 条因已存在而被跳过。`;
        }
        if (invalidCount > 0) {
            message += ` 另有 ${invalidCount} 条无效行被忽略。`;
        }
      
        return jsonResponse({ success: true, message: message }, 200);

    } catch (e) {
        console.error("D1 批量添加配置错误:", e);
        return jsonResponse({ error: '数据库批量操作失败: ' + e.message }, 500);
    }
}

async function handleGetConfigsByUuid(uuid, env) {
    if (!uuid) {
        return jsonResponse({ error: '缺少 UUID 参数。' }, 400);
    }
    const stmt = env.DB.prepare('SELECT id, uuid, config_data, protocol, remark, created_at, updated_at FROM configs WHERE uuid = ? ORDER BY id ASC');
    const { results } = await stmt.bind(uuid).all();

    if (results && results.length > 0) {
        return jsonResponse({ uuid: uuid, configs: results, message: `成功查询到 ${results.length} 条配置。` }, 200);
    } else {
        return jsonResponse({ error: `未找到 UUID 为 "${uuid}" 的任何配置。` }, 404);
    }
}

async function handleDeleteConfigsByUuid(uuid, env) {
    if (!uuid) {
        return jsonResponse({ error: '缺少 UUID 参数。' }, 400);
    }
    try {
        const stmt = env.DB.prepare('DELETE FROM configs WHERE uuid = ?');
        const { changes } = await stmt.bind(uuid).run();

        if (changes > 0) {
            return jsonResponse({ success: true, message: `成功删除 UUID "${uuid}" 下的全部 ${changes} 条配置。` }, 200);
        } else {
            return jsonResponse({ error: `未找到 UUID 为 "${uuid}" 的任何配置，无需删除。` }, 404);
        }
    } catch (e) {
        console.error("D1 按UUID删除错误:", e);
        return jsonResponse({ error: '数据库删除操作失败。' }, 500);
    }
}

async function handleDeleteSingleConfig(id, env) {
    if (!id || isNaN(parseInt(id))) {
        return jsonResponse({ error: 'ID 无效或缺失。' }, 400);
    }

    try {
        const stmt = env.DB.prepare('DELETE FROM configs WHERE id = ?');
        const { changes } = await stmt.bind(id).run();

        if (changes > 0) {
            return jsonResponse({ success: true, message: `ID 为 ${id} 的配置已成功删除。` });
        } else {
            return jsonResponse({ error: `未找到 ID 为 ${id} 的配置。` }, 404);
        }
    } catch (e) {
        console.error("D1 按ID删除错误:", e);
        return jsonResponse({ error: '数据库删除操作失败: ' + e.message }, 500);
    }
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

        const manageConfigsByUuidPattern = new URLPattern({ pathname: '/manage/configs/:uuid' });
        const manageConfigByIdPattern = new URLPattern({ pathname: '/manage/configs/id/:id' });
        const batchConfigsPattern = new URLPattern({ pathname: '/batch-configs/:uuid' });

        const manageConfigsByUuidMatch = manageConfigsByUuidPattern.exec(url);
        const manageConfigByIdMatch = manageConfigByIdPattern.exec(url);
        const batchConfigsMatch = batchConfigsPattern.exec(url);

        try { // [ADDED] Wrapping the router in a try...catch block for better error handling
            if (method === 'GET') {
                if (path === '/') {
                    const pageHtml = generatePageHtmlContent.replace(/YOUR_WORKER_DOMAIN_PATH/g, DOMAIN_NAME);
                    return new Response(pageHtml, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
                }
                if (path === '/manage') {
                    const pageHtml = managePageHtmlContent.replace(/YOUR_WORKER_DOMAIN_PATH/g, DOMAIN_NAME);
                    return new Response(pageHtml, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
                }
                if (path === '/batch-ip') {
                    return await handleGetBatchIps(url, env);
                }
                if (batchConfigsMatch) {
                    const uuid = batchConfigsMatch.pathname.groups.uuid;
                    const ipType = url.searchParams.get('ipType') || 'all';
                    // [FIXED] Corrected the typo from searchAtr to searchParams
                    const carrier = url.searchParams.get('carrier') || 'all';
                    return await handleGetBatchConfigs(uuid, ipType, carrier, env);
                }
            }

            if (path === '/generate' && method === 'POST') {
                return generateConfigs(request, env);
            }
            if (path === '/fetch-ips' && method === 'GET') {
                const ipType = url.searchParams.get('ipType') || 'all';
                const carrierType = url.searchParams.get('carrierType') || 'all';
                const ipSource = url.searchParams.get('source') || 'database'; 

                try {
                    if (ipSource === 'api') {
                        const apiResult = await fetchAndStoreIps(env);
                        if (!apiResult.success) {
                            console.warn(`用户触发的API更新失败: ${apiResult.error}`);
                            return jsonResponse({ error: `API更新失败: ${apiResult.error}` }, 500);
                        }
                    }
                    const ips = await fetchIpsFromDB(ipType, carrierType, env);
                    const responseData = { ips: ips.map(row => row.ip) };
                    if (ips.length === 0) {
                        responseData.message = "数据库中没有找到符合条件的 IP 地址。请尝试更新IP或检查定时任务。";
                    } else {
                        responseData.message = `成功从数据库获取 ${ips.length} 个IP。`;
                    }
                    return jsonResponse(responseData);
                } catch (e) {
                    console.error("Error in /fetch-ips:", e.message);
                    return jsonResponse({ error: "处理IP获取请求失败: " + e.message }, 500);
                }
            }

            if (path === '/manage/configs' && method === 'POST') {
                return await handleAddConfig(request, env);
            }
            if (manageConfigByIdMatch && method === 'DELETE') {
                const id = manageConfigByIdMatch.pathname.groups.id;
                return await handleDeleteSingleConfig(id, env);
            }
            if (manageConfigsByUuidMatch) {
                const uuid = manageConfigsByUuidMatch.pathname.groups.uuid;
                switch (method) {
                    case 'GET':
                        return await handleGetConfigsByUuid(uuid, env);
                    case 'DELETE':
                        return await handleDeleteConfigsByUuid(uuid, env);
                    default:
                        return jsonResponse({ error: `此路径不支持 ${method} 方法。` }, 405);
                }
            }
          
            return new Response('404 Not Found', { status: 404 });
        } catch (err) {
            // This global catch will handle any unexpected errors, including the typo fix.
            console.error("Caught a fatal error in the fetch handler:", err.stack);
            return new Response("An unexpected error occurred: " + err.message, { status: 500 });
        }
    },

    async scheduled(controller, env, ctx) {
        ctx.waitUntil(fetchAndStoreIps(env));
    }
};

// =================================================================
//  SECTION 3: HTML, CSS, AND JAVASCRIPT FOR FRONTEND (unchanged from last version)
// =================================================================

const newGlobalStyle = `
html { font-size: 87.5%; }
body, html { margin: 0; padding: 0; min-height: 100%; background-color: #fff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }

.container {
  width: 100%;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  padding: 40px 20px;
  box-sizing: border-box;
}

.content-group {
  width: 100%;
  max-width: 700px;
  text-align: center;
  z-index: 10;
  box-sizing: border-box;
}

.profile-name { font-size: 2.2rem; color: #3d474d; margin-bottom: 10px; font-weight: bold;}
.profile-quote { color: #89949B; margin-bottom: 27px; min-height: 1.2em; }

.nav-grid { display: flex; flex-wrap: wrap; justify-content: center; gap: 8px; margin-bottom: 27px; }
.nav-btn {
  padding: 8px 16px; text-align: center; background: #E8EBED; border: 2px solid #89949B;
  border-radius: 4px; color: #5a666d; text-decoration: none; font-weight: 500;
  font-size: 0.95rem; transition: all 0.3s; white-space: nowrap; cursor: pointer;
  display: inline-flex; align-items: center; justify-content: center;
}
.nav-btn:hover:not(:disabled) { background: #89949B; color: white; }
.nav-btn:disabled { opacity: 0.6; cursor: not-allowed;}
.nav-btn.primary { background-color: #5a666d; color: white; border-color: #5a666d;}
.nav-btn.primary:hover:not(:disabled) { background-color: #3d474d; }

.card {
  background: #f8f9fa; border: 1px solid #E8EBED; border-radius: 8px;
  padding: 24px; margin-bottom: 24px; text-align: left;
}
.card h2 { font-size: 1.5rem; color: #3d474d; margin-top: 0; margin-bottom: 20px; text-align: center;}
.form-group { margin-bottom: 16px; }
.form-group label { display: block; color: #5a666d; font-weight: 500; margin-bottom: 8px; font-size: 0.9rem;}
textarea, input[type="text"] {
  width: 100%; padding: 10px; border: 2px solid #89949B; border-radius: 4px;
  background: #fff; font-family: 'SF Mono', 'Courier New', monospace; font-size: 0.9rem;
  box-sizing: border-box; resize: vertical;
}
textarea:focus, input[type="text"]:focus { outline: none; border-color: #3d474d; }
.radio-group { display: flex; flex-wrap: wrap; gap: 10px; }
.radio-group label {
  padding: 6px 14px; background: #E8EBED; border: 2px solid #89949B;
  border-radius: 4px; color: #5a666d; font-size: 0.85rem; cursor: pointer;
  transition: all 0.3s;
}
.radio-group input[type="radio"] { display: none; }
.radio-group input[type="radio"]:checked + span { background: #89949B; color: white; }
.radio-group label:hover { background: #d1d5d8; }
.radio-group input[type="radio"]:checked + span:hover { background: #89949B; color: white; }

.info-box, .config-link-box {
  background-color: #e8ebed; color: #5a666d; border-left: 4px solid #89949B;
  padding: 12px 16px; border-radius: 4px; font-size: 0.85rem; text-align: left;
  line-height: 1.5; margin: 16px 0;
}
.info-box a, .config-link-box a { color: #3d474d; font-weight: bold; text-decoration: none; word-break: break-all; }
.info-box a:hover, .config-link-box a:hover { text-decoration: underline; }
.config-link-box button { padding: 4px 8px; font-size: 0.8rem; height: auto; border-radius: 3px; margin-left:10px; vertical-align: middle;}

.footer {
  margin-top: 40px; text-align: center; color: #89949B; font-size: 0.8rem;
}
.footer a { color: #89949B; text-decoration: none; }
.footer a:hover { text-decoration: underline; }
.hidden { display: none; }

#toast-container { position: fixed; top: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; }
.toast {
    display: flex; align-items: center; padding: 12px 18px; border-radius: 4px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.1); font-weight: 500; font-size: 0.9rem;
    border: 2px solid #89949B; background: #fff; color: #3d474d;
    opacity: 0; transform: translateX(100%);
    animation: slideIn 0.5s forwards, fadeOut 0.5s 4.5s forwards;
}
.toast svg { margin-right: 10px; width: 20px; height: 20px; }
@keyframes slideIn { to { opacity: 1; transform: translateX(0); } }
@keyframes fadeOut { from { opacity: 1; } to { opacity: 0; transform: translateX(100%); } }

.loader {
    width: 16px; height: 16px; border: 2px solid white;
    border-bottom-color: transparent; border-radius: 50%;
    display: inline-block; box-sizing: border-box;
    animation: rotation 1s linear infinite; margin-right: 8px;
}
@keyframes rotation { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
`;

const generatePageHtmlContent = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="https://s3.yangzihome.space/logo.ico" type="image/x-icon">
  <title>优选IP配置批量生成</title>
  <style>${newGlobalStyle}</style>
</head>
<body>
  <div id="toast-container"></div>
  <div class="container">
    <div class="content-group">
      <h1 class="profile-name">优选IP配置批量生成</h1>
      <p class="profile-quote">一个用于批量替换代理配置中IP地址的小工具</p>
      
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
        <h2>2. 优选IP列表</h2>
        <div class="form-group">
          <label>IP 类型</label>
          <div class="radio-group" id="genIpTypeGroup">
            <label><input type="radio" name="genIpType" value="all" checked><span>全部</span></label>
            <label><input type="radio" name="genIpType" value="v4"><span>仅IPv4</span></label>
            <label><input type="radio" name="genIpType" value="v6"><span>仅IPv6</span></label>
          </div>
        </div>
        <div class="form-group">
          <label>运营商</label>
          <div class="radio-group" id="genCarrierTypeGroup">
            <label><input type="radio" name="genCarrierType" value="all" checked><span>全部</span></label>
            <label><input type="radio" name="genCarrierType" value="CM"><span>移动</span></label>
            <label><input type="radio" name="genCarrierType" value="CU"><span>联通</span></label>
            <label><input type="radio" name="genCarrierType" value="CT"><span>电信</span></label>
          </div>
        </div>
        <div class="form-group">
            <label>IP 获取来源</label>
            <div class="radio-group" id="genIpSourceGroup">
                <label><input type="radio" name="genIpSource" value="database" checked><span>从数据库获取</span></label>
                <label><input type="radio" name="genIpSource" value="api"><span>从接口更新</span></label>
            </div>
        </div>
    
        <button id="genFetchIpButton" class="nav-btn" style="width:100%; margin-bottom: 16px;" onclick="genFetchAndPopulateIps()">获取优选IP</button>
        
        <div id="ipSubscriptionLinkBox" class="config-link-box hidden">
            <strong>IP 订阅链接:</strong> <a id="ipSubscriptionLink" href="#" target="_blank"></a>
            <button class="nav-btn" onclick="copyIpSubscriptionLink()">复制</button>
        </div>

        <textarea id="genIpListInput" placeholder="点击上方按钮获取，或在此手动粘贴IP地址列表..." rows="6"></textarea>
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
        <p>Powered by YZFN | <a href="https://www.yangzihome.space/security-statement" target="_blank" rel="noopener noreferrer">安全声明</a></p>
      </footer>
    </div>
  </div>

  <script>
    const WORKER_DOMAIN = "YOUR_WORKER_DOMAIN_PATH";
    const toastIcons = {
        success: \`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm-1.293-6.293a1 1 0 011.414 0L12 13.414l2.879-2.88a1 1 0 111.414 1.415l-3.586 3.586a1 1 0 01-1.414 0L8.707 13.121a1 1 0 010-1.414z" clip-rule="evenodd" /></svg>\`,
        error: \`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" /></svg>\`,
        info: \`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" /></svg>\`
    };
    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = \`\${toastIcons[type] || toastIcons.info}<span>\${message}</span>\`;
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 5000);
    }
    function setButtonLoading(button, isLoading, originalText) {
        if (isLoading) {
            button.disabled = true;
            button.innerHTML = \`<span class="loader"></span><span>处理中...</span>\`;
        } else {
            button.disabled = false;
            button.innerHTML = originalText;
        }
    }
    function toggleGenConfigSource() {
        const manualDiv = document.getElementById('genManualConfigInput');
        const uuidDiv = document.getElementById('genUuidConfigInput');
        const isManual = document.querySelector('input[name="genConfigSource"]:checked').value === 'manual';
        manualDiv.classList.toggle('hidden', !isManual);
        uuidDiv.classList.toggle('hidden', isManual);
        if (document.getElementById('generatedLinkBox')) {
            document.getElementById('generatedLinkBox').classList.add('hidden');
        }
    }
    async function genFetchAndPopulateIps() {
        const button = document.getElementById('genFetchIpButton');
        const originalText = button.innerHTML;
        setButtonLoading(button, true, originalText);
        const ipListInput = document.getElementById('genIpListInput');
        const ipSubscriptionLinkBox = document.getElementById('ipSubscriptionLinkBox');
        const ipSubscriptionLink = document.getElementById('ipSubscriptionLink');
        ipListInput.value = '';
        ipSubscriptionLinkBox.classList.add('hidden');
        const ipType = document.querySelector('input[name="genIpType"]:checked').value;
        const carrierType = document.querySelector('input[name="genCarrierType"]:checked').value;
        const source = document.querySelector('input[name="genIpSource"]:checked').value;
        const ipSubUrl = \`\${WORKER_DOMAIN}/batch-ip?ipType=\${encodeURIComponent(ipType)}&carrier=\${encodeURIComponent(carrierType)}\`;
        ipSubscriptionLink.href = ipSubUrl;
        ipSubscriptionLink.textContent = ipSubUrl;
        ipSubscriptionLinkBox.classList.remove('hidden');
        try {
            const response = await fetch(\`/fetch-ips?ipType=\${ipType}&carrierType=\${carrierType}&source=\${source}\`);
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || '服务器错误');
            if (data.ips && data.ips.length > 0) {
                ipListInput.value = data.ips.join('\\n');
                showToast(\`成功获取 \${data.ips.length} 个IP！\`, 'success');
            } else {
                showToast(data.message || '未找到符合条件的IP。', 'info');
            }
        } catch (error) {
            showToast('获取IP失败: ' + error.message, 'error');
        } finally {
            setButtonLoading(button, false, originalText);
        }
    }
    async function genGenerateConfigs() {
        const button = document.getElementById('genGenerateButton');
        const originalText = button.innerHTML;
        setButtonLoading(button, true, originalText);
        const resultTextarea = document.getElementById('genResultTextarea');
        resultTextarea.value = '';
        const generatedLinkBox = document.getElementById('generatedLinkBox');
        const generatedConfigLink = document.getElementById('generatedConfigLink');
        generatedLinkBox.classList.add('hidden');
        const source = document.querySelector('input[name="genConfigSource"]:checked').value;
        const body = { ipList: document.getElementById('genIpListInput').value };
        let baseConfigUuid = '';
        if (source === 'manual') {
            body.baseConfig = document.getElementById('genBaseConfigInput').value;
        } else {
            baseConfigUuid = document.getElementById('genBaseConfigUuidInput').value.trim();
            body.baseConfigUuid = baseConfigUuid;
        }
        if ((!body.baseConfig && !body.baseConfigUuid) || !body.ipList) {
            showToast('基础配置和IP列表均不能为空！', 'error');
            setButtonLoading(button, false, originalText);
            return;
        }
        try {
            const response = await fetch('/generate', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(body)
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || '生成失败');
            const successConfigs = data.configs.filter(c => !c.startsWith('[错误]'));
            resultTextarea.value = data.configs.join('\\n');
            showToast(data.message || '生成成功！', 'success');
            if (source === 'uuid' && baseConfigUuid && successConfigs.length > 0) {
                const ipType = document.querySelector('input[name="genIpType"]:checked').value;
                const carrierType = document.querySelector('input[name="genCarrierType"]:checked').value;
                const fullUrl = \`\${WORKER_DOMAIN}/batch-configs/\${encodeURIComponent(baseConfigUuid)}?ipType=\${encodeURIComponent(ipType)}&carrier=\${encodeURIComponent(carrierType)}\`;
                generatedConfigLink.href = fullUrl;
                generatedConfigLink.textContent = fullUrl;
                generatedLinkBox.classList.remove('hidden');
            }
        } catch (error) {
            showToast('生成配置失败: ' + error.message, 'error');
            resultTextarea.value = '错误：\\n' + error.message;
        } finally {
            setButtonLoading(button, false, originalText);
        }
    }
    function copyResults() {
        const textarea = document.getElementById('genResultTextarea');
        if (!textarea.value) {
            showToast('没有结果可复制。', 'info'); return;
        }
        const configsToCopy = textarea.value.split('\\n').filter(c => !c.startsWith('[错误]')).join('\\n');
        navigator.clipboard.writeText(btoa(configsToCopy)).then(() => {
            showToast('结果已Base64编码并复制！', 'success');
        }, () => { showToast('复制失败。', 'error'); });
    }
    function copyGeneratedLink() {
        const link = document.getElementById('generatedConfigLink');
        if (!link || !link.href || link.href.endsWith('#')) { showToast('无链接可复制。', 'info'); return; }
        navigator.clipboard.writeText(link.href).then(() => { showToast('订阅链接已复制！', 'success'); }, () => { showToast('复制失败。', 'error'); });
    }
    function copyIpSubscriptionLink() {
        const link = document.getElementById('ipSubscriptionLink');
        if (!link || !link.href || link.href.endsWith('#')) { showToast('无链接可复制。', 'info'); return; }
        navigator.clipboard.writeText(link.href).then(() => { showToast('IP订阅链接已复制！', 'success'); }, () => { showToast('复制失败。', 'error'); });
    }
    document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('input[name="genConfigSource"]').forEach(radio => radio.addEventListener('change', toggleGenConfigSource));
        toggleGenConfigSource();
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
  <link rel="icon" href="https://s3.yangzihome.space/logo.ico" type="image/x-icon">
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

      <footer class="footer">
        <p>Powered by YZFN | <a href="https://www.yangzihome.space/security-statement" target="_blank" rel="noopener noreferrer">安全声明</a></p>
      </footer>
    </div>
  </div>

  <script>
    const toastIcons = {
        success: \`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm-1.293-6.293a1 1 0 011.414 0L12 13.414l2.879-2.88a1 1 0 111.414 1.415l-3.586 3.586a1 1 0 01-1.414 0L8.707 13.121a1 1 0 010-1.414z" clip-rule="evenodd" /></svg>\`,
        error: \`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" /></svg>\`,
        info: \`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" /></svg>\`
    };
    function showToast(message, type = 'info') {
      const container = document.getElementById('toast-container');
      const toast = document.createElement('div');
      toast.className = 'toast';
      toast.innerHTML = \`\${toastIcons[type] || toastIcons.info}<span>\${message}</span>\`;
      container.appendChild(toast);
      setTimeout(() => toast.remove(), 5000);
    }
    function setButtonLoading(button, isLoading, originalText = '') {
        if (isLoading) {
            button.disabled = true;
            button.dataset.originalText = button.innerHTML;
            button.innerHTML = \`<span class="loader"></span><span>处理中...</span>\`;
        } else {
            button.disabled = false;
            button.innerHTML = originalText || button.dataset.originalText;
        }
    }
    async function manageQueryByUuid() {
        const button = document.getElementById('queryBtn');
        const originalText = button.innerHTML;
        setButtonLoading(button, true, originalText);
        const uuid = document.getElementById('queryUuidInput').value.trim();
        const resultsContainer = document.getElementById('queryResultsContainer');
        if (!uuid) {
            showToast('请输入要查询的UUID。', 'error');
            setButtonLoading(button, false, originalText);
            return;
        }
        try {
            const response = await fetch(\`/manage/configs/\${uuid}\`);
            const data = await response.json();
            document.getElementById('addUuidInput').value = uuid;
            if (response.status === 404) {
                 resultsContainer.innerHTML = '<p class="placeholder">未找到此 UUID 的配置。</p>';
                 showToast('未找到配置。', 'info');
                 return;
            }
            if (!response.ok) throw new Error(data.error || '未知错误');
            if (data.configs && data.configs.length > 0) {
                let tableHtml = '<div class="table-container"><table><thead><tr><th>ID</th><th>备注</th><th>协议</th><th class="config-data-cell">配置数据</th><th class="actions-cell">操作</th></tr></thead><tbody>';
                data.configs.forEach(config => {
                    tableHtml += \`<tr>
                      <td>\${config.id}</td>
                      <td>\${config.remark || '---'}</td>
                      <td>\${config.protocol}</td>
                      <td class="config-data-cell" title="\${config.config_data}">\${config.config_data}</td>
                      <td class="actions-cell">
                        <button class="nav-btn" style="background-color:#d44" onclick="manageDeleteSingleConfig(event, \${config.id})">删除</button>
                      </td>
                    </tr>\`;
                });
                tableHtml += '</tbody></table></div>';
                resultsContainer.innerHTML = tableHtml;
                showToast(\`成功查询到 \${data.configs.length} 条配置。\`, 'success');
            } else {
                resultsContainer.innerHTML = '<p class="placeholder">此 UUID 下没有配置。</p>';
            }
        } catch (error) {
            resultsContainer.innerHTML = \`<p class="placeholder" style="color:red;">查询失败: \${error.message}</p>\`;
            showToast(\`查询失败: \${error.message}\`, 'error');
        } finally {
            setButtonLoading(button, false, originalText);
        }
    }
    async function manageAddConfig() {
      const button = document.getElementById('addConfigBtn');
      const originalText = button.innerHTML;
      setButtonLoading(button, true, originalText);
      const uuid = document.getElementById('addUuidInput').value.trim();
      const config_data = document.getElementById('addConfigData').value.trim();
      try {
        if (!uuid || !config_data) throw new Error("UUID 和配置数据不能为空。");
        const response = await fetch('/manage/configs', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ uuid, config_data })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || '未知错误');
        showToast(data.message, 'success');
        document.getElementById('addConfigData').value = '';
        if (uuid === document.getElementById('queryUuidInput').value.trim()) {
            await manageQueryByUuid();
        }
      } catch (error) {
        showToast(\`添加失败: \${error.message}\`, 'error');
      } finally {
        setButtonLoading(button, false, originalText);
      }
    }
    async function manageDeleteGroupdByUuid() {
        const uuid = document.getElementById('queryUuidInput').value.trim();
        if (!uuid) { showToast('请输入要删除的 UUID。', 'error'); return; }
        if (!confirm(\`确定要删除 UUID "\${uuid}" 的【所有】配置吗？此操作不可撤销！\`)) return;
        const button = document.getElementById('deleteBtn');
        const originalText = button.innerHTML;
        setButtonLoading(button, true, originalText);
        try {
            const response = await fetch(\`/manage/configs/\${uuid}\`, { method: 'DELETE' });
            const data = await response.json();
            if (!response.ok && response.status !== 404) throw new Error(data.error || '未知错误');
            showToast(data.message || data.error, response.ok ? 'success' : 'info');
            if (uuid === document.getElementById('queryUuidInput').value.trim()) {
                 document.getElementById('queryResultsContainer').innerHTML = '<p class="placeholder">此UUID的所有配置已删除。</p>';
            }
        } catch(e) {
            showToast(\`删除失败: \${e.message}\`, 'error');
        } finally {
            setButtonLoading(button, false, originalText);
        }
    }
    async function manageDeleteSingleConfig(event, configId) {
        if (!configId) return;
        if (!confirm(\`确定要删除 ID 为 \${configId} 的这条配置吗？\`)) return;
        const button = event.currentTarget;
        const originalText = button.innerHTML;
        setButtonLoading(button, true, '...');
        try {
            const response = await fetch(\`/manage/configs/id/\${configId}\`, { method: 'DELETE' });
            if (!response.ok) {
                const data = await response.json(); throw new Error(data.error || '未知错误');
            }
            showToast(\`配置 ID \${configId} 已删除。\`, 'success');
            await manageQueryByUuid();
        } catch (e) {
            showToast(\`删除失败: \${e.message}\`, 'error');
            setButtonLoading(button, false, originalText);
        }
    }
  </script>
</body>
</html>
`;
