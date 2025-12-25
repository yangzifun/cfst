/* =================================================================
 * Cloudflare Worker: IP Management Worker
 * 修复版 v3：自动修复数据库表结构 (Schema Migration)
 * 解决：table cfips has no column named updated_at
 * 修改：更新前先清理原数据库所有IP (全量替换)
 * ================================================================= */

// =================================================================
//  1. 常量定义
// =================================================================
const DEFAULT_JWT_SECRET = 'your-default-jwt-secret-change-this';

// =================================================================
//  2. 工具函数
// =================================================================

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

// =================================================================
//  3. IP获取函数
// =================================================================

async function fetchIpsFromHostMonit(type = 'v4') {
    try {
        const requestBody = { key: "iDetkOys" };
        if (type === 'v6') requestBody.type = 'v6';
        
        const res = await fetch('https://api.hostmonit.com/get_optimization_ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });
        
        if (!res.ok) return [];
        const data = await res.json();
        
        if (data.code === 200 && Array.isArray(data.info)) {
            return data.info.map(i => {
                let carrier = i.line || 'ALL';
                if (carrier === 'CMI') carrier = 'CM';
                if (carrier === 'CT') carrier = 'CT';
                if (carrier === 'CU') carrier = 'CU';
                return {
                    ip: i.ip,
                    ip_type: i.ip.includes(':') ? 'v6' : 'v4',
                    carrier: carrier,
                    source: `hostmonit_${type}`
                };
            });
        }
        return [];
    } catch (e) { 
        console.error(`fetchIpsFromHostMonit error:`, e.message);
        return []; 
    }
}

async function fetchIpsFromVps789() {
    try {
        const res = await fetch('https://vps789.com/openApi/cfIpApi', { 
            headers: { 'User-Agent': 'CF-Worker/4.0', 'Accept': 'application/json' } 
        });
        
        if (!res.ok) return [];
        const data = await res.json();
        const ips = [];
        
        if (data.code === 0 && data.data) {
            for (const k in data.data) {
                const arr = data.data[k];
                if (Array.isArray(arr)) {
                    let carrier = 'ALL';
                    if (k.includes('移动') || k.includes('CM') || k === 'CM') carrier = 'CM';
                    else if (k.includes('电信') || k.includes('CT') || k === 'CT') carrier = 'CT';
                    else if (k.includes('联通') || k.includes('CU') || k === 'CU') carrier = 'CU';
                    
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
        }
        return ips;
    } catch (e) { 
        console.error('fetchIpsFromVps789 error:', e.message);
        return []; 
    }
}

// =================================================================
//  4. 核心逻辑 (含数据库修复)
// =================================================================

/**
 * 关键修复：检查并自动升级数据库表结构
 */
async function ensureSchema(env) {
    try {
        // 1. 确保表存在
        await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS cfips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                ip_type TEXT,
                carrier TEXT,
                source TEXT,
                created_at INTEGER,
                updated_at INTEGER
            )
        `).run();

        // 2. 检查旧表是否缺少 updated_at 列 (Migration)
        // D1 不支持直接检查 columns 存在性，需要查询 pragma
        const info = await env.DB.prepare('PRAGMA table_info(cfips)').all();
        const columns = (info.results || []).map(c => c.name);
        
        if (!columns.includes('updated_at')) {
            console.log('检测到旧表结构，正在添加 updated_at 列...');
            await env.DB.prepare('ALTER TABLE cfips ADD COLUMN updated_at INTEGER').run();
        }
        
        // 3. 确保设置表存在
        await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS auto_update_settings (
                source TEXT PRIMARY KEY,
                enabled INTEGER,
                updated_at INTEGER
            )
        `).run();

    } catch (e) {
        console.error('Schema check/update failed:', e);
        // 如果 ALTER TABLE 失败，可能是因为在事务中或权限问题，但通常 D1 支持简单的 ALTER
    }
}

async function executeInChunks(stmts) {
    const CHUNK_SIZE = 10; 
    for (let i = 0; i < stmts.length; i += CHUNK_SIZE) {
        const chunk = stmts.slice(i, i + CHUNK_SIZE);
        await Promise.all(chunk.map(stmt => stmt.run()));
    }
}

async function runIpUpdateTask(env, sources = null) {
    console.log('开始IP全量更新任务...');
    
    // --- 0. 确保数据库结构正确 ---
    await ensureSchema(env);
    
    // --- 1. 获取配置 ---
    if (sources === null) {
        try {
            const settingsRes = await env.DB.prepare(
                'SELECT source, enabled FROM auto_update_settings WHERE source IN (?, ?, ?, ?)'
            ).bind('hostmonit_v4', 'hostmonit_v6', 'vps789', 'global_enabled').all();
            
            if (settingsRes && settingsRes.results) {
                sources = {};
                settingsRes.results.forEach(setting => { sources[setting.source] = setting.enabled === 1; });
            } else {
                sources = { hostmonit_v4: true, hostmonit_v6: false, vps789: true, global_enabled: true };
            }
        } catch (e) {
            sources = { hostmonit_v4: true, hostmonit_v6: false, vps789: true, global_enabled: true };
        }
    }

    // --- 2. 获取数据 ---
    const tasks = [];
    if (sources.hostmonit_v4 !== false) tasks.push(fetchIpsFromHostMonit('v4'));
    if (sources.hostmonit_v6 !== false) tasks.push(fetchIpsFromHostMonit('v6'));
    if (sources.vps789 !== false) tasks.push(fetchIpsFromVps789());

    if (tasks.length === 0) return { success: false, message: "没有启用的API源" };

    const results = await Promise.allSettled(tasks);
    const allIps = [];
    const sourceStats = {};

    results.forEach((result, index) => {
        const sourceNames = ['hostmonit_v4', 'hostmonit_v6', 'vps789'];
        const sourceName = index < sourceNames.length ? sourceNames[index] : `Source_${index}`;
        
        if (result.status === 'fulfilled') {
            const ips = result.value;
            allIps.push(...ips);
            sourceStats[sourceName] = { count: ips.length, status: 'ok' };
        } else {
            sourceStats[sourceName] = { count: 0, status: 'error' };
        }
    });

    console.log(`API共获取到 ${allIps.length} 个原始IP`);

    // --- 3. 去重 ---
    const uniqueMap = new Map();
    allIps.forEach(i => { 
        if (i && i.ip) {
            const normalizedIp = i.ip.trim();
            const carrier = i.carrier || 'ALL';
            const key = `${normalizedIp}_${carrier}`;
            
            if (!uniqueMap.has(key)) {
                uniqueMap.set(key, { ...i, ip: normalizedIp, carrier: carrier });
            } else {
                const existing = uniqueMap.get(key);
                if (existing.source && i.source && !existing.source.includes(i.source)) {
                    existing.source = `${existing.source}|${i.source}`;
                }
            }
        }
    });
    
    const newIpList = Array.from(uniqueMap.values());
    console.log(`去重后得到 ${newIpList.length} 个有效记录`);

    if (sources.global_enabled === 0) {
        return { success: true, count: newIpList.length, message: "自动更新已关闭" };
    }

    try {
        // --- 4. 清理原数据库中的所有IP ---
        console.log('清理原数据库中所有IP记录...');
        await env.DB.prepare('DELETE FROM cfips').run();
        
        // --- 5. 插入新IP数据 ---
        let insertedCount = 0;
        if (newIpList.length > 0) {
            console.log(`插入 ${newIpList.length} 个新IP记录...`);
            
            const insertStmts = newIpList.map(i =>
                env.DB.prepare('INSERT INTO cfips (ip, ip_type, carrier, source, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
                    .bind(i.ip, i.ip_type || 'v4', i.carrier, i.source, Date.now(), Date.now())
            );
            
            await executeInChunks(insertStmts);
            insertedCount = newIpList.length;
        }

        // --- 6. 更新最后执行时间 ---
        await env.DB.prepare('INSERT OR REPLACE INTO auto_update_settings (source, enabled, updated_at) VALUES (?, ?, ?)')
            .bind('last_executed', 1, Date.now()).run();

        return { 
            success: true, 
            message: `更新成功 (清理了所有旧IP，插入了${insertedCount}个新IP)`,
            sourceStats,
            stats: {
                cleaned: true,
                inserted: insertedCount
            }
        };

    } catch (e) {
        console.error('Database Sync Error:', e.message);
        return { success: false, message: "DB Error: " + e.message };
    }
}

async function initializeDatabaseSettings(env) {
    try {
        await ensureSchema(env); // 复用统一的Schema检查
        
        const defaultSettings = [
            { source: 'global_enabled', enabled: 1 },
            { source: 'hostmonit_v4', enabled: 1 },
            { source: 'hostmonit_v6', enabled: 0 },
            { source: 'vps789', enabled: 1 },
            { source: 'last_executed', enabled: 0 }
        ];
        
        for (const setting of defaultSettings) {
            await env.DB.prepare('INSERT OR IGNORE INTO auto_update_settings (source, enabled, updated_at) VALUES (?, ?, ?)')
                .bind(setting.source, setting.enabled, Date.now())
                .run();
        }
    } catch (e) {
        console.error('Init Settings Error:', e.message);
    }
}

// =================================================================
//  5. API处理
// =================================================================

async function handleManualIpUpdate(req, env) {
    return jsonResponse(await runIpUpdateTask(env));
}

async function handleGetIpList(req, env) {
    try {
        await ensureSchema(env); // 确保读取时表也是好的
        
        const url = new URL(req.url);
        const page = parseInt(url.searchParams.get('page')) || 1;
        const size = parseInt(url.searchParams.get('size')) || 20;
        const offset = (page - 1) * size;

        const total = await env.DB.prepare('SELECT COUNT(*) as c FROM cfips').first('c');
        const { results } = await env.DB.prepare('SELECT * FROM cfips ORDER BY created_at DESC LIMIT ? OFFSET ?').bind(size, offset).all();
        const carrierStats = await env.DB.prepare(`SELECT carrier, COUNT(*) as count FROM cfips GROUP BY carrier`).all();

        return jsonResponse({ 
            total: total || 0, 
            data: results || [], 
            stats: { carrier_stats: carrierStats.results || [] }
        });
    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

// =================================================================
//  6. 入口
// =================================================================

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        ctx.waitUntil(initializeDatabaseSettings(env));

        if (url.pathname === '/api/ips/list') return await handleGetIpList(request, env);
        if (url.pathname === '/api/ips/update') return await handleManualIpUpdate(request, env);
        
        return new Response(JSON.stringify({ status: 'running', version: '3.0.0' }), { headers: { 'Content-Type': 'application/json' } });
    },
    
    async scheduled(event, env, ctx) {
        ctx.waitUntil((async () => {
            await initializeDatabaseSettings(env);
            await runIpUpdateTask(env);
        })());
    }
};
