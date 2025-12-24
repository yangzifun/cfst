/* =================================================================
 * Cloudflare Worker: IP Management Worker
 * 专门处理IP更新任务，支持定时更新和手动更新接口
 * ================================================================= */

// =================================================================
//  1. 常量定义
// =================================================================
const DEFAULT_JWT_SECRET = 'your-default-jwt-secret-change-this';

// =================================================================
//  2. 工具函数
// =================================================================

// JSON响应
function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), { 
        status, 
        headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-cache, no-store'
        } 
    });
}

// JWT验证（当前代码中未使用，但保留以备未来扩展）
async function verifyJwt(token, secret = DEFAULT_JWT_SECRET) {
    try {
        const [h, p, s] = token.split('.');
        if (!h || !p || !s) return false;
        const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
        const signature = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
        const valid = await crypto.subtle.verify('HMAC', key, signature, new TextEncoder().encode(`${h}.${p}`));
        if (!valid) return false;
        const payload = JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')));
        if (payload.exp < Date.now()) return false;
        return payload;
    } catch (e) { return false; }
}

// =================================================================
//  3. IP获取函数（修复IPv6数据解析问题）
// =================================================================

async function fetchIpsFromHostMonit(type = 'v4') {
    try {
        const requestBody = { key: "iDetkOys" };
        if (type === 'v6') {
            requestBody.type = 'v6';
        }
        
        const res = await fetch('https://api.hostmonit.com/get_optimization_ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });
        
        if (!res.ok) {
            console.error(`HostMonit ${type} API响应错误: ${res.status}`);
            return [];
        }
        
        const data = await res.json();
        console.log(`HostMonit ${type} 返回数据:`, JSON.stringify(data).substring(0, 500));
        
        if (data.code === 200 && Array.isArray(data.info)) {
            return data.info.map(i => {
                // 标准化运营商标识
                let carrier = i.line || 'ALL';
                if (carrier === 'CMI') carrier = 'CM'; // 标准化为'CM'
                if (carrier === 'CT') carrier = 'CT';
                if (carrier === 'CU') carrier = 'CU';
                
                return {
                    ip: i.ip,  // 直接使用IP，不添加方括号
                    ip_type: i.ip.includes(':') ? 'v6' : 'v4',
                    carrier: carrier,
                    source: `hostmonit_${type}`
                };
            });
        } else {
            console.error(`HostMonit ${type} 数据格式错误:`, data);
            return [];
        }
    } catch (e) { 
        console.error(`fetchIpsFromHostMonit ${type} error:`, e.message);
        return []; 
    }
}

async function fetchIpsFromVps789() {
    try {
        const res = await fetch('https://vps789.com/openApi/cfIpApi', { 
            headers: { 
                'User-Agent': 'CF-Worker/4.0',
                'Accept': 'application/json'
            } 
        });
        
        if (!res.ok) {
            console.error('Vps789 API响应错误:', res.status);
            return [];
        }
        
        const data = await res.json();
        console.log('Vps789 返回数据结构:', Object.keys(data));
        
        const ips = [];
        if (data.code === 0 && data.data) {
            // 调试输出数据结构
            console.log('Vps789 data.keys:', Object.keys(data.data));
            
            // 处理所有可能的键
            for (const k in data.data) {
                const arr = data.data[k];
                console.log(`处理Vps789键: ${k}, 数据类型:`, Array.isArray(arr) ? '数组' : typeof arr);
                
                if (Array.isArray(arr)) {
                    // 标准化运营商标识
                    let carrier = 'ALL';
                    if (k.includes('移动') || k.includes('CM')) carrier = 'CM';
                    else if (k.includes('电信') || k.includes('CT')) carrier = 'CT';
                    else if (k.includes('联通') || k.includes('CU')) carrier = 'CU';
                    else if (k === 'ALL') carrier = 'ALL';
                    else if (k === 'CM') carrier = 'CM';
                    else if (k === 'CT') carrier = 'CT';
                    else if (k === 'CU') carrier = 'CU';
                    
                    console.log(`Vps789 键 ${k} 标准化为运营商: ${carrier}, IP数量: ${arr.length}`);
                    
                    arr.forEach(i => {
                        if (i && i.ip) {
                            ips.push({
                                ip: i.ip,
                                ip_type: i.ip.includes(':') ? 'v6' : 'v4',
                                carrier: carrier,
                                source: 'vps789'
                            });
                        }
                    });
                }
            }
        } else {
            console.error('Vps789数据格式错误:', data);
        }
        
        console.log(`Vps789 总共获取到 ${ips.length} 个IP`);
        return ips;
    } catch (e) { 
        console.error('fetchIpsFromVps789 error:', e.message);
        return []; 
    }
}

// =================================================================
//  4. 核心IP更新任务函数（增强调试信息）
// =================================================================

/**
 * 执行IP更新任务
 * @param {Object} env - Cloudflare Worker环境变量
 * @param {Object} sources - 更新源配置（可选，为null时从数据库读取）
 * @returns {Promise<Object>} 更新结果
 */
async function runIpUpdateTask(env, sources = null) {
    console.log('开始IP更新任务...');
    
    if (sources === null) {
        try {
            const settingsRes = await env.DB.prepare(
                'SELECT source, enabled FROM auto_update_settings WHERE source IN (?, ?, ?, ?)'
            ).bind('hostmonit_v4', 'hostmonit_v6', 'vps789', 'global_enabled').all();
            
            if (settingsRes && settingsRes.results) {
                sources = {};
                settingsRes.results.forEach(setting => {
                    sources[setting.source] = setting.enabled === 1;
                });
                console.log('从数据库读取的更新设置:', sources);
            } else {
                sources = { 
                    hostmonit_v4: true, 
                    hostmonit_v6: false,  // 默认不开启V6
                    vps789: true, 
                    global_enabled: true 
                };
                console.log('使用默认更新设置:', sources);
            }
        } catch (e) {
            console.error('获取自动更新设置失败，使用默认值:', e.message);
            sources = { 
                hostmonit_v4: true, 
                hostmonit_v6: false,
                vps789: true, 
                global_enabled: true 
            };
        }
    }

    const tasks = [];
    const taskSources = [];
    
    if (sources.hostmonit_v4 !== false) {
        tasks.push(fetchIpsFromHostMonit('v4'));
        taskSources.push('hostmonit_v4');
    }
    if (sources.hostmonit_v6 !== false) {
        tasks.push(fetchIpsFromHostMonit('v6'));
        taskSources.push('hostmonit_v6');
    }
    if (sources.vps789 !== false) {
        tasks.push(fetchIpsFromVps789());
        taskSources.push('vps789');
    }

    if (tasks.length === 0) {
        console.log("没有启用的API源");
        return { success: false, message: "没有启用的API源" };
    }

    console.log(`启用的任务: ${taskSources.join(', ')}`);
    const results = await Promise.allSettled(tasks);
    
    const allIps = [];
    const sourceStats = {};
    
    results.forEach((result, index) => {
        const sourceName = taskSources[index];
        if (result.status === 'fulfilled') {
            const ips = result.value;
            console.log(`${sourceName} 获取到 ${ips.length} 个IP`);
            
            // 按运营商统计
            const carrierStats = {};
            const ipTypeStats = { v4: 0, v6: 0 };
            
            ips.forEach(i => {
                if (i && i.ip) {
                    // 标准化运营商
                    const carrier = i.carrier || 'ALL';
                    carrierStats[carrier] = (carrierStats[carrier] || 0) + 1;
                    
                    // 统计IP类型
                    const ipType = i.ip.includes(':') ? 'v6' : 'v4';
                    ipTypeStats[ipType] = (ipTypeStats[ipType] || 0) + 1;
                    
                    allIps.push(i);
                }
            });
            
            sourceStats[sourceName] = {
                count: ips.length,
                carrierStats,
                ipTypeStats
            };
            
            console.log(`${sourceName} 运营商分布:`, carrierStats);
            console.log(`${sourceName} IP类型分布:`, ipTypeStats);
        } else {
            console.error(`${sourceName} 任务失败:`, result.reason);
            sourceStats[sourceName] = {
                error: result.reason?.message || '未知错误',
                count: 0
            };
        }
    });

    console.log(`总共获取到 ${allIps.length} 个IP`);
    
    const uniqueMap = new Map();
    allIps.forEach(i => { 
        if (i && i.ip) {
            const normalizedIp = i.ip.trim();
            if (!uniqueMap.has(normalizedIp)) {
                uniqueMap.set(normalizedIp, { ...i, ip: normalizedIp });
            } else {
                // 合并来源信息
                const existing = uniqueMap.get(normalizedIp);
                if (existing.source && !existing.source.includes(i.source)) {
                    existing.source = `${existing.source}|${i.source}`;
                }
            }
        }
    });
    
    const uniqueIps = Array.from(uniqueMap.values());
    console.log(`去重后剩余 ${uniqueIps.length} 个唯一IP`);

    // 最终统计
    const finalCarrierStats = {};
    const finalIpTypeStats = { v4: 0, v6: 0 };
    
    uniqueIps.forEach(i => {
        const carrier = i.carrier || 'ALL';
        finalCarrierStats[carrier] = (finalCarrierStats[carrier] || 0) + 1;
        
        const ipType = i.ip.includes(':') ? 'v6' : 'v4';
        finalIpTypeStats[ipType] = (finalIpTypeStats[ipType] || 0) + 1;
    });
    
    console.log('最终运营商分布:', finalCarrierStats);
    console.log('最终IP类型分布:', finalIpTypeStats);

    if (uniqueIps.length === 0) {
        return { 
            success: false, 
            message: "未能获取到任何有效IP", 
            count: 0,
            sourceStats
        };
    }

    try {
        const globalSetting = sources.global_enabled;
        
        if (globalSetting === 0) {
            return { 
                success: true, 
                count: uniqueIps.length, 
                message: `获取到 ${uniqueIps.length} 个IP，但自动更新已关闭`,
                data: uniqueIps.slice(0, 10),
                carrierStats: finalCarrierStats,
                sourceStats
            };
        }

        await env.DB.prepare('DELETE FROM cfips').run();
        console.log('已清空cfips表');
        
        const stmts = uniqueIps.map(i =>
            env.DB.prepare('INSERT INTO cfips (ip, ip_type, carrier, source, created_at) VALUES (?, ?, ?, ?, ?)')
                .bind(i.ip, i.ip_type || (i.ip.includes(':') ? 'v6' : 'v4'), 
                      i.carrier || 'ALL', i.source || 'unknown', Date.now())
        );
        
        const BATCH_SIZE = 50;
        for (let i = 0; i < stmts.length; i += BATCH_SIZE) {
            const batch = stmts.slice(i, i + BATCH_SIZE);
            await env.DB.batch(batch);
            console.log(`批量插入 ${i} 到 ${i+BATCH_SIZE-1} 的IP`);
        }
        
        await env.DB.prepare(
            'INSERT OR REPLACE INTO auto_update_settings (source, enabled, updated_at) VALUES (?, ?, ?)'
        ).bind('last_executed', 1, Date.now()).run();
        
        console.log(`IP更新完成: ${uniqueIps.length}条记录`);
        return { 
            success: true, 
            count: uniqueIps.length, 
            message: `成功更新 ${uniqueIps.length} 个 IP`,
            timestamp: Date.now(),
            carrierStats: finalCarrierStats,
            ipTypeStats: finalIpTypeStats,
            sourceStats
        };
        
    } catch (e) {
        console.error('IP更新任务数据库操作失败:', e.message);
        return { 
            success: false, 
            message: "数据库错误: " + e.message,
            sourceStats
        };
    }
}

// 初始化默认自动更新设置
async function initializeDatabaseSettings(env) {
    try {
        const defaultSettings = [
            { source: 'global_enabled', enabled: 1, updated_at: Date.now() },
            { source: 'hostmonit_v4', enabled: 1, updated_at: Date.now() },
            { source: 'hostmonit_v6', enabled: 0, updated_at: Date.now() }, // 默认不开启IPv6
            { source: 'vps789', enabled: 1, updated_at: Date.now() },
            { source: 'last_executed', enabled: 0, updated_at: 0 }
        ];
        
        // 使用 INSERT OR IGNORE 确保只在不存在时插入
        const stmts = defaultSettings.map(setting =>
            env.DB.prepare(
                'INSERT OR IGNORE INTO auto_update_settings (source, enabled, updated_at) VALUES (?, ?, ?)'
            ).bind(setting.source, setting.enabled, setting.updated_at)
        );
        await env.DB.batch(stmts);
        
        console.log('数据库设置初始化完成或已存在');
    } catch (e) {
        console.error('数据库设置初始化失败:', e.message);
    }
}

// =================================================================
//  5. API处理函数
// =================================================================

/**
 * 处理手动更新接口（GET请求，无需认证）
 */
async function handleManualIpUpdate(req, env) {
    try {
        console.log('手动触发IP更新');
        const res = await runIpUpdateTask(env, null);
        return jsonResponse(res);
    } catch (error) {
        console.error('handleManualIpUpdate error:', error.message);
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

/**
 * 获取IP列表（只读接口，无需认证）
 */
async function handleGetIpList(req, env) {
    try {
        const url = new URL(req.url);
        const page = parseInt(url.searchParams.get('page')) || 1;
        const size = parseInt(url.searchParams.get('size')) || 20;
        const sortField = url.searchParams.get('sort') || 'created_at';
        const sortOrder = (url.searchParams.get('order') || 'desc').toUpperCase() === 'ASC' ? 'ASC' : 'DESC';
        
        const allowedSorts = ['ip', 'ip_type', 'carrier', 'source', 'created_at'];
        const actualSort = allowedSorts.includes(sortField) ? sortField : 'created_at';
        const offset = (page - 1) * size;

        const total = await env.DB.prepare('SELECT COUNT(*) as c FROM cfips').first('c');
        const query = `SELECT * FROM cfips ORDER BY ${actualSort} ${sortOrder} LIMIT ? OFFSET ?`;
        const { results } = await env.DB.prepare(query).bind(size, offset).all();
        
        // 统计信息
        const stats = await env.DB.prepare(`
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN ip_type = 'v6' THEN 1 ELSE 0 END) as v6_count,
                carrier,
                COUNT(*) as carrier_count
            FROM cfips 
            GROUP BY carrier
        `).all();

        return jsonResponse({ 
            total: total || 0, 
            data: results || [], 
            page, 
            size,
            stats: stats.results || []
        });
    } catch (error) {
        console.error('handleGetIpList error:', error.message);
        return jsonResponse({ error: '服务器错误' }, 500);
    }
}

// =================================================================
//  6. 主API路由处理
// =================================================================

async function handleApi(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    try {
        // 无需认证的API
        if (path === '/api/ips/list' && method === 'GET') {
            return await handleGetIpList(req, env);
        }
        
        // 手动更新接口（GET请求，无需认证）
        if (path === '/api/ips/update' && method === 'GET') {
            return await handleManualIpUpdate(req, env);
        }
        
        return jsonResponse({ error: 'API端点不存在' }, 404);
        
    } catch (error) {
        console.error('API处理错误:', error);
        return jsonResponse({ error: '服务器内部错误: ' + error.message }, 500);
    }
}

// =================================================================
//  7. 主入口
// =================================================================

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        
        // 确保数据库设置已初始化
        ctx.waitUntil(initializeDatabaseSettings(env));

        // 处理API请求
        if (url.pathname.startsWith('/api')) {
            return await handleApi(request, env);
        }
        
        // 默认返回简单的状态页面
        return new Response(JSON.stringify({
            service: 'IP Management Worker',
            status: 'running',
            version: '2.0.0',
            endpoints: {
                public: [
                    'GET /api/ips/list - 获取IP列表（带统计信息）',
                    'GET /api/ips/update - 手动触发IP更新（带详细日志）'
                ]
            },
            note: '此服务专用于IP更新任务，自动更新设置由mg_worker.js管理'
        }, null, 2), { 
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            } 
        });
    },
    
    async scheduled(event, env, ctx) {
        ctx.waitUntil((async () => {
            console.log('定时IP更新任务开始执行');
            await initializeDatabaseSettings(env); // 确保定时任务前设置已初始化
            try {
                const res = await runIpUpdateTask(env);
                console.log(`定时IP更新任务完成: ${res.message}`);
            } catch (error) {
                console.error('定时IP更新任务失败:', error);
            }
        })());
    }
};
