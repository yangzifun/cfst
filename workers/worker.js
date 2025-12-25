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
//  SECTION 0: Access Logging
// =================================================================

/**
 * 记录配置访问日志
 * @param {Object} env - Worker环境变量
 * @param {string} uuid - 用户UUID
 * @param {string} queryType - 查询类型: 'subscription'(订阅) 或 'api-generation'(网页生成)
 * @param {string} clientIp - 客户端IP地址
 * @param {string} userAgent - 客户端User-Agent
 */
async function logConfigAccess(env, uuid, queryType, clientIp, userAgent) {
    try {
        const db = env.DB;
        if (!db) {
            console.error("D1数据库未绑定，无法记录访问日志");
            return;
        }
        
        const stmt = db.prepare(
            'INSERT INTO config_access_logs (uuid, query_type, client_ip, user_agent) VALUES (?, ?, ?, ?)'
        );
        
        await stmt.bind(uuid, queryType, clientIp || 'unknown', userAgent || 'unknown').run();
        console.log(`成功记录访问日志: uuid=${uuid}, type=${queryType}`);
    } catch (e) {
        console.error("记录访问日志失败:", e.message);
        // 不中断主流程，仅记录错误
    }
}

/**
 * 获取客户端IP地址 (支持Cloudflare Worker)
 * @param {Request} request - HTTP请求对象
 * @returns {string} 客户端IP地址
 */
function getClientIp(request) {
    // Cloudflare Workers可以通过cf-connecting-ip头获取真实IP
    const cfIp = request.headers.get('cf-connecting-ip');
    if (cfIp) return cfIp;
    
    // 回退到X-Forwarded-For
    const forwardedFor = request.headers.get('x-forwarded-for');
    if (forwardedFor) {
        // 取第一个IP（原始客户端IP）
        return forwardedFor.split(',')[0].trim();
    }
    
    // 最终回退方案
    return 'unknown';
}

/**
 * 获取访问统计
 * @param {Object} env - Worker环境变量
 * @param {string} uuid - UUID（可选，不提供则查询所有）
 * @param {Object} options - 查询选项
 * @returns {Promise<Object>} 统计结果
 */
async function getAccessStats(env, uuid = null, options = {}) {
    try {
        const db = env.DB;
        if (!db) throw new Error("D1数据库未绑定。");
        
        let query = 'SELECT uuid, query_type, COUNT(*) as count, DATE(created_at) as date FROM config_access_logs WHERE 1=1';
        const params = [];
        
        if (uuid) {
            query += ' AND uuid = ?';
            params.push(uuid);
        }
        
        // 时间范围过滤
        if (options.startDate) {
            query += ' AND created_at >= ?';
            params.push(options.startDate);
        }
        
        if (options.endDate) {
            query += ' AND created_at <= ?';
            params.push(options.endDate);
        }
        
        query += ' GROUP BY uuid, query_type, DATE(created_at) ORDER BY date DESC, count DESC';
        
        const { results } = await db.prepare(query).bind(...params).all();
        return { success: true, data: results };
    } catch (e) {
        console.error("获取访问统计失败:", e.message);
        return { success: false, error: e.message };
    }
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

// 读取基础配置 (SELECT) - 修改：增加域名托管字段查询
async function fetchConfigsByUuidFromDB(uuid, env) {
    const db = env.DB;
    if (!db) return [];
    try {
        const stmt = db.prepare('SELECT id, config_data, protocol, remark, domain_hosting FROM configs WHERE uuid = ? ORDER BY id ASC');
        const { results } = await stmt.bind(uuid).all();
        return results;  // 返回完整对象，包含domain_hosting字段
    } catch (e) {
        console.error(`Error fetching configs for UUID ${uuid}:`, e.message);
        return [];
    }
}

// 核心替换逻辑 - 修改：确保所有原配置都被输出，但只有Cloudflare配置进行优选替换
function replaceAddressesInConfigs(baseConfigsData, addressList) {
    let generatedConfigs = [];
    const addressExtractionRegex = /@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9a-fA-F:\.]+\]|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?::\d+)?(?:[\/?#]|$)/;
    const validAddressRegex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9a-fA-F:\.]+\]|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})$/;

    for (const configObj of baseConfigsData) {
        const baseConfig = configObj.config_data;
        const domainHosting = configObj.domain_hosting || 'Cloudflare'; // 默认为Cloudflare
        const configId = configObj.id || 0;
        const remark = configObj.remark || '';
        
        let configType = getProtocol(baseConfig);
        let processedBaseConfig;
        const pushError = (msg) => generatedConfigs.push(`[错误] ${msg}`);

        // 首先，无论域名属性是什么，先输出原配置
        generatedConfigs.push(baseConfig);
        
        // 检查域名托管属性，只有Cloudflare的配置才进行优选替换
        if (domainHosting !== 'Cloudflare') {
            // 非Cloudflare配置只输出原配置，不进行优选替换
            console.log(`配置ID ${configId} 的域名托管属性为"${domainHosting}"，只输出原配置，不进行优选替换`);
            continue;  // 跳过优选替换循环
        }
        
        // 只处理 vmess, vless, trojan 协议
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
            pushError(`不支持的类型: ${configType}，已跳过。`);
            continue;
        }

        // 对Cloudflare配置进行优选替换
        for (const newAddr of addressList) {
            if (!validAddressRegex.test(newAddr) && !newAddr.includes(':')) {
                // simple validation
            }
            const cleanAddrForName = newAddr.replace(/[\[\]]/g, '');
            
            // 处理IPv6地址格式
            let formattedAddr = newAddr;
            if (newAddr.includes(':') && !newAddr.startsWith('[') && !newAddr.endsWith(']')) {
                formattedAddr = `[${newAddr}]`;
            }

            if (configType === 'trojan' || configType === 'vless') {
                try {
                    const url = new URL(processedBaseConfig);
                    const originalName = url.hash ? decodeURIComponent(url.hash.substring(1)) : `${configType}-node`;
                    const newName = `${originalName}-${cleanAddrForName}`;
                    url.hash = encodeURIComponent(newName);
                    url.hostname = formattedAddr; 
                    generatedConfigs.push(url.toString());
                } catch (e) {
                    pushError(`处理 ${configType} 出错: ${e.message}`);
                }
            } else if (configType === 'vmess') {
                const tempVmessObj = JSON.parse(JSON.stringify(processedBaseConfig));
                const originalName = tempVmessObj.ps || tempVmessObj.remark || 'vmess-node';
                tempVmessObj.ps = `${originalName}-${cleanAddrForName}`;
                
                // 处理IPv6地址格式
                let formattedAddr = newAddr;
                if (newAddr.includes(':') && !newAddr.startsWith('[') && !newAddr.endsWith(']')) {
                    formattedAddr = `[${newAddr}]`;
                }
                tempVmessObj.add = formattedAddr; 
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

// 手动 or UUID 生成 (POST) - 修改：适应新的数据结构
async function generateConfigs(request, env) {
    try {
        const body = await request.json();
        const addressListText = body.addressList || body.ipList;
        const { baseConfigUuid, baseConfig: baseConfigFromRequest } = body;
        
        let baseConfigsData = [];

        if (baseConfigUuid) {
            const configsFromDb = await fetchConfigsByUuidFromDB(baseConfigUuid, env);
            if (configsFromDb.length === 0) {
                return jsonResponse({ error: `未找到 UUID 为 "${baseConfigUuid}" 的任何基础配置。` }, 404);
            }
            baseConfigsData = configsFromDb;
            
            // 统计域名托管类型
            const hostingStats = {};
            configsFromDb.forEach(cfg => {
                const hosting = cfg.domain_hosting || 'Cloudflare';
                hostingStats[hosting] = (hostingStats[hosting] || 0) + 1;
            });
            console.log(`UUID ${baseConfigUuid} 域名托管统计:`, hostingStats);
            
        } else if (baseConfigFromRequest) {
            // 手动粘贴的配置没有domain_hosting信息，全部按照Cloudflare处理（进行优选替换）
            const configLines = baseConfigFromRequest.split('\n').map(s => s.trim()).filter(Boolean);
            if (configLines.length === 0) return jsonResponse({ error: "基础配置不能为空。" }, 400);
            
            baseConfigsData = configLines.map((config_data, index) => ({
                id: index,
                config_data,
                protocol: getProtocol(config_data),
                remark: null,
                domain_hosting: 'Cloudflare' // 手动粘贴的配置默认为Cloudflare，进行优选替换
            }));
        } else {
            return jsonResponse({ error: "必须提供基础配置或UUID。" }, 400);
        }

        if (!addressListText || addressListText.trim() === '') {
            return jsonResponse({ error: "优选列表不能为空。" }, 400);
        }

        const addressList = addressListText.split('\n').map(a => a.trim()).filter(a => a.length > 0);
        const generatedConfigs = replaceAddressesInConfigs(baseConfigsData, addressList);

        // 统计生成结果
        const totalConfigs = baseConfigsData.length;
        const cloudflareConfigs = baseConfigsData.filter(cfg => cfg.domain_hosting === 'Cloudflare').length;
        const otherHostingCount = totalConfigs - cloudflareConfigs;
        
        // 计算成功条数（排除错误消息）
        const successCount = generatedConfigs.filter(c => !c.startsWith('[错误]')).length;
        const errorCount = generatedConfigs.length - successCount;
        
        // 计算预期输出条数
        const expectedNonCloudflare = otherHostingCount; // 每个非Cloudflare配置输出1条原配置
        const expectedCloudflare = cloudflareConfigs * (addressList.length + 1); // 每个Cloudflare配置输出1条原配置 + addressList.length条优选配置
        const expectedTotal = expectedNonCloudflare + expectedCloudflare;
        
        let message = `生成完成！成功 ${successCount} 条，预期输出 ${expectedTotal} 条`;
        if (errorCount > 0) message += `，失败 ${errorCount} 条`;
        
        // 添加域名托管过滤信息
        if (otherHostingCount > 0) {
            message += ` (注：其中有 ${otherHostingCount} 个非Cloudflare配置只输出原配置，${cloudflareConfigs} 个Cloudflare配置进行了优选替换)`;
        }
        
        // 如果使用UUID生成，记录访问日志
        if (baseConfigUuid) {
            const clientIp = getClientIp(request);
            const userAgent = request.headers.get('user-agent') || 'unknown';
            await logConfigAccess(env, baseConfigUuid, 'api-generation', clientIp, userAgent);
        }
        
        return jsonResponse({ 
            configs: generatedConfigs, 
            message: message,
            stats: {
                total_configs: totalConfigs,
                cloudflare_configs: cloudflareConfigs,
                other_hosting_configs: otherHostingCount,
                address_list_count: addressList.length,
                expected_output: expectedTotal,
                actual_output: successCount
            }
        });
    } catch (e) {
        console.error("生成配置出错:", e.message);
        return jsonResponse({ error: "内部错误: " + e.message }, 500);
    }
}

// 订阅链接生成配置 (GET) - 修改：适应新的数据结构
async function handleGetBatchConfigs(uuid, urlParams, env, request) {
    if (!uuid) return jsonResponse({ error: 'UUID Required' }, 400);

    const baseConfigsData = await fetchConfigsByUuidFromDB(uuid, env);
    if (baseConfigsData.length === 0) return jsonResponse({ error: `UUID Not Found` }, 404);
    
    // 统计数据
    const totalConfigs = baseConfigsData.length;
    const cloudflareConfigs = baseConfigsData.filter(cfg => cfg.domain_hosting === 'Cloudflare').length;
    const otherConfigs = totalConfigs - cloudflareConfigs;
    
    console.log(`订阅UUID ${uuid}: 总配置数${totalConfigs}, Cloudflare配置${cloudflareConfigs}, 其他域名托管配置${otherConfigs}`);

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

    const generatedConfigs = replaceAddressesInConfigs(baseConfigsData, addressList);
    const filteredConfigs = generatedConfigs.filter(c => !c.startsWith('[错误]'));

    if (filteredConfigs.length === 0) {
        return new Response("Generation failed.", { status: 400 });
    }

    const body = btoa(filteredConfigs.join('\n'));

    // 记录订阅访问日志
    const clientIp = getClientIp(request);
    const userAgent = request.headers.get('user-agent') || 'unknown';
    await logConfigAccess(env, uuid, 'subscription', clientIp, userAgent);

    return new Response(body, {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=UTF-8',
            'Subscription-User-Info': 'upload=0; download=0; total=10737418240000; expire=2524608000',
            'Profile-Update-Interval': '24',
            // 添加域名托管过滤信息头
            'X-Domain-Hosting-Filter': `Cloudflare=${cloudflareConfigs}, Other=${otherConfigs}`
        },
    });
}

// =================================================================
//  ADMIN API (用于后台管理统计)
// =================================================================

/**
 * 处理访问统计API请求
 */
async function handleAccessStats(request, env, url) {
    const uuid = url.searchParams.get('uuid');
    const startDate = url.searchParams.get('start_date');
    const endDate = url.searchParams.get('end_date');
    
    const options = {};
    if (startDate) options.startDate = startDate;
    if (endDate) options.endDate = endDate;
    
    const stats = await getAccessStats(env, uuid, options);
    
    if (!stats.success) {
        return jsonResponse({ error: `获取统计失败: ${stats.error}` }, 500);
    }
    
    // 计算汇总统计
    const summary = {
        total_requests: stats.data.reduce((sum, item) => sum + item.count, 0),
        unique_uuids: [...new Set(stats.data.map(item => item.uuid))].length,
        subscription_requests: stats.data
            .filter(item => item.query_type === 'subscription')
            .reduce((sum, item) => sum + item.count, 0),
        api_generation_requests: stats.data
            .filter(item => item.query_type === 'api-generation')
            .reduce((sum, item) => sum + item.count, 0)
    };
    
    // 按日期统计
    const dailyStats = {};
    stats.data.forEach(item => {
        if (!dailyStats[item.date]) {
            dailyStats[item.date] = {
                total: 0,
                subscription: 0,
                api_generation: 0,
                uuids: new Set()
            };
        }
        dailyStats[item.date].total += item.count;
        dailyStats[item.date].uuids.add(item.uuid);
        
        if (item.query_type === 'subscription') {
            dailyStats[item.date].subscription += item.count;
        } else if (item.query_type === 'api-generation') {
            dailyStats[item.date].api_generation += item.count;
        }
    });
    
    // 转换为数组格式便于前端显示
    const dailyStatsArray = Object.entries(dailyStats).map(([date, data]) => ({
        date,
        total: data.total,
        subscription: data.subscription,
        api_generation: data.api_generation,
        unique_uuids: data.uuids.size
    })).sort((a, b) => new Date(b.date) - new Date(a.date)); // 按日期降序
    
    return jsonResponse({
        summary,
        daily_stats: dailyStatsArray,
        raw_data: stats.data
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
                    return await handleGetBatchConfigs(batchMatch.pathname.groups.uuid, url.searchParams, env, request);
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
                
                // Admin API: 访问统计 (可添加认证机制)
                if (path === '/admin/stats') {
                    // 这里可以添加认证逻辑，例如检查API密钥
                    // const apiKey = url.searchParams.get('api_key');
                    // if (apiKey !== env.ADMIN_API_KEY) {
                    //     return jsonResponse({ error: 'Unauthorized' }, 401);
                    // }
                    return await handleAccessStats(request, env, url);
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
  <title>代理配置生成</title>
  <style>${newGlobalStyle}</style>
</head>
<body>
  <div id="toast-container"></div>
  <div class="container">
    <div class="content-group">
      <h1 class="profile-name">代理配置批量生成</h1>
      <p class="profile-quote">支持 IP 优选与域名优选的批量替换工具</p>

      <div class="nav-grid">
        <a href="/" class="nav-btn primary">批量生成</a>
        <a href="https://config-cfst.api.yangzifun.org/" target="_blank" class="nav-btn">配置管理</a>
      </div>

      <div class="card">
        <h2>1. 基础配置</h2>
        <div class="form-group">
          <div class="info-box">
            <strong>注意：</strong> 所有配置都会输出原配置。
            <br>域名托管属性为"Cloudflare"的配置会进行优选替换（每条原配置 + 优选地址数条新配置）。
            <br>其他域名托管配置（如阿里ESA、腾讯Edgeone、AWS Cloudfront、Gcore、Fastly等）只输出原配置，不进行优选替换。
          </div>
        </div>
        <div class="form-group radio-group">
            <label><input type="radio" name="genConfigSource" value="manual" checked><span>手动粘贴</span></label>
            <label><input type="radio" name="genConfigSource" value="uuid"><span>从UUID获取</span></label>
        </div>
        <div id="genManualConfigInput" class="form-group">
            <textarea id="genBaseConfigInput" placeholder="在此粘贴一个或多个基础配置，每行一个。" rows="6"></textarea>
        </div>
        <div id="genUuidConfigInput" class="form-group hidden">
            <input type="text" id="genBaseConfigUuidInput" placeholder="输入已存储的UUID，如 my-configs">
            <div class="info-box">在 <a href="https://config-cfst.api.yangzifun.org/" target="_blank">配置管理</a> 页面添加和管理UUID。
            <br>所有配置都会输出原配置，只有域名托管属性为"Cloudflare"的配置会进行优选替换。</div>
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
        <textarea id="genResultTextarea" readonly placeholder="点击下方"生成配置"按钮..." rows="8"></textarea>
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
                
                // 显示统计信息
                if (data.stats) {
                    console.log("生成统计:", data.stats);
                }
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
